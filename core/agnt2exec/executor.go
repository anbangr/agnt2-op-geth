// Package agnt2exec is the AGNT2 native typed-VM executor (research-grade T3, the
// spine's executor half — "full-layer-core-typed-vm").
//
// It applies the full per-op transition pipeline for a typed op (INVOKE / RESPOND /
// COMPOSE — there is no TIMEOUT typed op) as ONE composed, instrumented step, so the
// paper can measure composed-µs/op against its 5–10 µs budget. The seven pipeline
// stages and how each is realized here:
//
//	(a) format / sig check          — REAL: types.Sender (ECDSA recover) + typed-op field decode
//	(b) escrow lock / release       — MODELED with REAL StateDB writes (no escrow exists in Go;
//	                                   it is ERC20 state in AgentWorkflow.sol). COMPOSE settles:
//	                                   one escrow-slot read+write + AddBalance to each of StepCount agents.
//	(c) interaction-trie write      — MODELED with a REAL StateDB storage write per op (append leaf).
//	(d) reputation counter          — MODELED with a REAL StateDB read-modify-write per settled agent.
//	(e) TTL deadline-heap           — MODELED with REAL StateDB writes (heap push).
//	(f) DA-commitment               — REAL for INVOKE (types.AGNT2InvokeReexecOutput, the exported,
//	                                   golden-locked derivation); a keccak over the payload models the
//	                                   marginal hash cost for RESPOND/COMPOSE (whose authoritative
//	                                   derivation needs parent / block context — supplied at block level).
//	(g) block-manifest append       — REAL at block level: ExecuteBlock delegates the fraud root to the
//	                                   exported types.FoldTypedReexecRoot and the persistent ring write to
//	                                   agnt2store.ProcessReexecStore.
//
// HONESTY. Stages (b),(d),(e) and the DA-post half of (f) do not exist as Go state
// today; they are modeled with REAL StateDB operations (not sleeps) sized to their
// Solidity/spec footprint, so the composed cost is a genuine measurement of the
// state-write + hashing work, clearly labeled as a model where it is one. The
// FRAUD-COMMITMENT root is never re-derived here — ExecuteBlock delegates it to
// types.FoldTypedReexecRoot, the same golden-locked derivation AGNT2StepVerifier
// uses. Delegating the fold FUNCTION is necessary but NOT sufficient for
// byte-equality: the block-level evict/fold ORDERING must also match production
// (ProcessReexecStore before the fold — see ExecuteBlock), else a RESPOND at the
// W-block eviction boundary diverges. Both are locked by tests
// (TestExecutor_ReexecRootMatchesFold + the cross-block W-boundary test).
package agnt2exec

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/agnt2store"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// Synthetic system accounts for the modeled state effects. Distinct addresses keep
// the escrow / reputation / trie / TTL keyspaces from colliding; the ring uses the
// real reserved account so ExecuteBlock's ProcessReexecStore write is the production one.
var (
	escrowAddr = common.HexToAddress("0x000000000000000000000000000000000A6E5C70") // escrow FSM + balances
	repAddr    = common.HexToAddress("0x000000000000000000000000000000000A6E9E70") // reputation counters
	trieAddr   = common.HexToAddress("0x000000000000000000000000000000000A6E7815") // interaction-trie leaves
	ttlAddr    = common.HexToAddress("0x000000000000000000000000000000000A6E7771") // TTL deadline heap
	ringAddr   = params.AGNT2ReexecStoreAddr                                        // real re-exec ring (0xA9E2)

	systemAccounts = []common.Address{escrowAddr, repAddr, trieAddr, ttlAddr, ringAddr}
)

// slot derivations mirror the domain-separated single-byte-prefix scheme used by
// core/agnt2store (prefixes there are 0x01..0x04; these use disjoint prefixes).
func escrowSlot(wf common.Hash) common.Hash   { return crypto.Keccak256Hash([]byte{0x10}, wf[:]) }
func repSlot(agent common.Address) common.Hash {
	return crypto.Keccak256Hash([]byte{0x11}, agent[:])
}
func trieLeafSlot(wf common.Hash, step uint8) common.Hash {
	return crypto.Keccak256Hash([]byte{0x12}, wf[:], []byte{step})
}
func ttlSlot(wf common.Hash) common.Hash { return crypto.Keccak256Hash([]byte{0x13}, wf[:]) }
func ringOutSlot(txHash common.Hash) common.Hash {
	return crypto.Keccak256Hash([]byte{0x01}, txHash[:]) // matches agnt2store.slotOut
}

// StepMetrics records what one composed step actually did, so the measurement can
// attribute cost and so tests can assert the pipeline touched the right keyspaces.
type StepMetrics struct {
	OpType       uint8
	StateReads   int
	StateWrites  int
	BalanceMoves int
	Hashes       int // keccak invocations attributable to the DA-commitment stage
	Skipped      bool
	SkipReason   string
}

// Result is the outcome of one composed step.
type Result struct {
	OutputHash common.Hash // INVOKE: the real committed output; RESPOND/COMPOSE: block-level (see ExecuteBlock)
	Metrics    StepMetrics
}

// Executor holds the immutable config for a run.
type Executor struct {
	signer types.Signer
	cfg    *params.ChainConfig
}

// New builds an executor. signer must match the chain the txs were signed for.
func New(signer types.Signer, cfg *params.ChainConfig) *Executor {
	return &Executor{signer: signer, cfg: cfg}
}

// EnsureSystemAccounts creates the modeled system accounts so SetState/AddBalance
// land on existing objects. Call once against a fresh StateDB before stepping.
func (e *Executor) EnsureSystemAccounts(sdb vm.StateDB) {
	for _, a := range systemAccounts {
		if !sdb.Exist(a) {
			sdb.CreateAccount(a)
		}
	}
}

// ComposedStep applies one typed op's full transition pipeline against sdb and
// returns its Result. It is the unit the benchmark times for composed-µs/op. The
// fraud-commitment root is NOT computed here (see ExecuteBlock).
func (e *Executor) ComposedStep(sdb vm.StateDB, tx *types.Transaction) (Result, error) {
	var m StepMetrics
	m.OpType = stepType(tx)

	// (a) format / sig check — real ECDSA recover + typed-op decode.
	agent, err := types.Sender(e.signer, tx)
	if err != nil {
		return Result{Metrics: m}, err
	}

	switch tx.Type() {
	case types.InvokeTxType:
		return e.stepInvoke(sdb, tx, agent, m)
	case types.RespondTxType:
		return e.stepRespond(sdb, tx, agent, m)
	case types.ComposeTypedTxType:
		return e.stepCompose(sdb, tx, agent, m)
	default:
		m.Skipped, m.SkipReason = true, "not a typed op"
		return Result{Metrics: m}, nil
	}
}

func (e *Executor) stepInvoke(sdb vm.StateDB, tx *types.Transaction, agent common.Address, m StepMetrics) (Result, error) {
	opId, ok := tx.Agnt2OperationID()
	if !ok {
		m.Skipped, m.SkipReason = true, "no operation id"
		return Result{Metrics: m}, nil
	}
	wf := opId.WorkflowId

	// (c) interaction-trie append (one real storage write).
	sdb.SetState(trieAddr, trieLeafSlot(wf, opId.StepId), leafHash(wf, agent, tx.Data()))
	m.StateWrites++

	// (e) TTL deadline-heap push (one real storage write).
	sdb.SetState(ttlAddr, ttlSlot(wf), common.BytesToHash([]byte{1}))
	m.StateWrites++

	// (f) DA-commitment — the REAL, golden-locked INVOKE derivation.
	out, _ := types.AGNT2InvokeReexecOutput(tx, e.signer)
	m.Hashes += 2 // inputCommitment + outputHash keccaks

	// INVOKE is request-only: no escrow move, no reputation write. The persistent
	// ring write happens at block level (agnt2store.ProcessReexecStore).
	return Result{OutputHash: out, Metrics: m}, nil
}

func (e *Executor) stepRespond(sdb vm.StateDB, tx *types.Transaction, agent common.Address, m StepMetrics) (Result, error) {
	opId, ok := tx.Agnt2OperationID()
	if !ok {
		m.Skipped, m.SkipReason = true, "no operation id"
		return Result{Metrics: m}, nil
	}
	deps := tx.Agnt2Dependencies()
	if len(deps) == 0 {
		m.Skipped, m.SkipReason = true, "no invoke ref"
		return Result{Metrics: m}, nil
	}
	// (a cont.) parent read — the RW conflict with the parent INVOKE's ring write.
	parentOut := sdb.GetState(ringAddr, ringOutSlot(deps[0]))
	m.StateReads++

	// (c) interaction-trie append.
	sdb.SetState(trieAddr, trieLeafSlot(opId.WorkflowId, opId.StepId), leafHash(opId.WorkflowId, agent, tx.Data()))
	m.StateWrites++
	// (e) TTL push.
	sdb.SetState(ttlAddr, ttlSlot(opId.WorkflowId), common.BytesToHash([]byte{2}))
	m.StateWrites++

	// (f) DA-commitment marginal hash cost (authoritative RESPOND output is folded at
	// block level, which needs the resolved parentOut — supplied by the ring/resolver).
	_ = crypto.Keccak256Hash(parentOut[:], tx.Data())
	m.Hashes++
	return Result{Metrics: m}, nil
}

func (e *Executor) stepCompose(sdb vm.StateDB, tx *types.Transaction, agent common.Address, m StepMetrics) (Result, error) {
	wf, ok := tx.Agnt2ComposeWorkflowId()
	if !ok {
		m.Skipped, m.SkipReason = true, "no workflow id"
		return Result{Metrics: m}, nil
	}
	n := int(composeStepCount(tx))

	// (b) escrow settle: read the escrow FSM slot, write it SETTLED, release payout to
	// each of the n workflow agents (real balance moves — the heaviest op, fan-in n).
	_ = sdb.GetState(escrowAddr, escrowSlot(wf))
	m.StateReads++
	sdb.SetState(escrowAddr, escrowSlot(wf), common.BytesToHash([]byte{settledFlag}))
	m.StateWrites++
	payout := uint256.NewInt(1)
	for i := 0; i < n; i++ {
		ag := composeAgent(wf, i)
		sdb.AddBalance(ag, payout, tracing.BalanceChangeTransfer)
		m.BalanceMoves++
		// (d) reputation counter: read-modify-write the per-agent counter.
		cur := sdb.GetState(repAddr, repSlot(ag))
		m.StateReads++
		sdb.SetState(repAddr, repSlot(ag), incHash(cur))
		m.StateWrites++
	}

	// (c) interaction-trie append for the COMPOSE leaf itself.
	sdb.SetState(trieAddr, trieLeafSlot(wf, composeStepCount(tx)), leafHash(wf, agent, nil))
	m.StateWrites++

	// (f) DA-commitment marginal hash cost over the childOutputHashes (32·n bytes).
	_ = crypto.Keccak256Hash(make([]byte, 32*n))
	m.Hashes++
	return Result{Metrics: m}, nil
}

// BlockResult is the outcome of executing a whole block of typed ops.
type BlockResult struct {
	ReexecRoot common.Hash // authoritative fraud root — delegated to types.FoldTypedReexecRoot
	OpCount    uint64
	Folded     uint64 // leaves the fold committed (skips excluded)
	Steps      []StepMetrics
}

// ExecuteBlock runs the composed step for every typed op in the block, then evicts +
// writes the ring (agnt2store.ProcessReexecStore) and delegates the authoritative
// fraud-commitment root to the exported, golden-locked types.FoldTypedReexecRoot — in
// that order (see the note at stage (g)). Delegation + matching the evict-then-fold
// ordering together keep the executor byte-equal to the on-chain fraud gate, including
// at the W-block eviction boundary (locked by TestExecutor_ReexecRootMatchesFold and
// TestExecutor_CrossBlockEvictionMatchesFold).
func (e *Executor) ExecuteBlock(sdb vm.StateDB, header *types.Header, txs []*types.Transaction) (BlockResult, error) {
	e.EnsureSystemAccounts(sdb)
	res := BlockResult{OpCount: uint64(len(txs))}
	for _, tx := range txs {
		r, err := e.ComposedStep(sdb, tx)
		if err != nil {
			return res, err
		}
		res.Steps = append(res.Steps, r.Metrics)
	}
	// (g) block-manifest append. ORDER MATTERS and must match production
	// (beacon.Finalize -> ProcessReexecStore, THEN fold): evict + write the ring
	// FIRST, then fold. Folding first would read the ring PRE-eviction and could fold
	// a RESPOND whose parent INVOKE is exactly W blocks old — a parent the chain
	// evicts (an M6 skip) — diverging from the fraud gate at the eviction boundary.
	// Writing this block's own INVOKEs before the fold is a no-op for resolution: the
	// Resolver's strictly-prior guard (blk >= curBlockNum => miss) rejects them and the
	// fold serves same-block parents from its in-block map.
	agnt2store.ProcessReexecStore(sdb, e.cfg, header, txs)
	resolver := agnt2store.Resolver(sdb, header.Number.Uint64())
	root, folded := types.FoldTypedReexecRoot(txs, e.signer, resolver)
	res.ReexecRoot, res.Folded = root, folded
	return res, nil
}

// --- helpers ---

const (
	settledFlag = 0x02
)

func stepType(tx *types.Transaction) uint8 {
	switch tx.Type() {
	case types.InvokeTxType:
		return 1
	case types.RespondTxType:
		return 2
	case types.ComposeTypedTxType:
		return 3
	default:
		return 0
	}
}

func composeStepCount(tx *types.Transaction) uint8 {
	if n, ok := tx.Agnt2ComposeStepCount(); ok {
		return n
	}
	return 0
}

// leafHash models the interaction-trie leaf value written per op (a realistic 32-byte
// keccak the executor stores; not the consensus interaction-root leaf, which is folded
// from receipts at block level).
func leafHash(wf common.Hash, agent common.Address, data []byte) common.Hash {
	return crypto.Keccak256Hash(wf[:], agent[:], data)
}

func incHash(cur common.Hash) common.Hash {
	v := new(uint256.Int).SetBytes(cur[:])
	v.AddUint64(v, 1)
	return v.Bytes32()
}

// composeAgent derives a deterministic synthetic agent address for the i-th settled
// step of workflow wf, so fan-in n produces n distinct balance/reputation writes.
func composeAgent(wf common.Hash, i int) common.Address {
	h := crypto.Keccak256Hash([]byte{0x20}, wf[:], []byte{byte(i), byte(i >> 8)})
	return common.BytesToAddress(h[12:])
}
