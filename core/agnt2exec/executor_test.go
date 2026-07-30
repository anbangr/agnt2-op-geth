package agnt2exec

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// Fixed key => deterministic tx hashes => a lockable reexec root.
const fixedKeyHex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

func newState(t *testing.T) *state.StateDB {
	t.Helper()
	sdb, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		t.Fatal(err)
	}
	return sdb
}

func fixedKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := crypto.HexToECDSA(fixedKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// a workflow of INVOKE -> RESPOND (child of the invoke) -> COMPOSE (fan-in 2).
func workflowBlock(t *testing.T, signer types.Signer, key *ecdsa.PrivateKey, cid *big.Int) []*types.Transaction {
	t.Helper()
	wf := common.HexToHash("0xC0")
	invoke, err := types.SignNewTx(key, signer, &types.InvokeTx{
		ChainID: cid, Nonce: 0, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
		Gas: 100000, WorkflowId: wf, StepId: 1, AgentRole: "worker", DepInvokeIds: []common.Hash{}, Payload: []byte("call"),
	})
	if err != nil {
		t.Fatal(err)
	}
	respond, err := types.SignNewTx(key, signer, &types.RespondTx{
		ChainID: cid, Nonce: 1, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
		Gas: 100000, WorkflowId: wf, StepId: 2, InvokeRef: invoke.Hash(), ResponsePayload: []byte("resp"), Status: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	compose, err := types.SignNewTx(key, signer, &types.ComposeTypedTx{
		ChainID: cid, Nonce: 2, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
		Gas: 200000, WorkflowId: wf, StepCount: 2,
		StepWorkflowRoots: []common.Hash{common.HexToHash("0x0a"), common.HexToHash("0x0b")},
		Payouts:           []*big.Int{big.NewInt(1), big.NewInt(2)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return []*types.Transaction{invoke, respond, compose}
}

// TestExecutor_ReexecRootMatchesFold is THE byte-equality gate: the executor's
// committed re-exec root must equal types.FoldTypedReexecRoot over the same block —
// the exact derivation the on-chain AGNT2StepVerifier is golden-locked to (see
// core/types/agnt2_reexec_test.go). Delegation makes the executor transitively
// byte-equal to Solidity; this test proves ExecuteBlock actually delegates and does
// not compute a divergent root.
func TestExecutor_ReexecRootMatchesFold(t *testing.T) {
	cfg := params.OptimismTestConfig
	header := &types.Header{Number: big.NewInt(100), Time: 0}
	signer := types.MakeSigner(cfg, header.Number, header.Time)
	key := fixedKey(t)
	txs := workflowBlock(t, signer, key, cfg.ChainID)

	sdb := newState(t)
	exec := New(signer, cfg)
	res, err := exec.ExecuteBlock(sdb, header, txs)
	if err != nil {
		t.Fatalf("ExecuteBlock: %v", err)
	}

	// same-block INVOKE->RESPOND resolves via the in-block map, so a nil-resolver
	// recompute must equal the executor's delegated root.
	want, wantN := types.FoldTypedReexecRoot(txs, signer, nil)
	if res.ReexecRoot != want {
		t.Fatalf("executor root drift from fraud-gate fold:\n got %s\nwant %s", res.ReexecRoot.Hex(), want.Hex())
	}
	if res.Folded != wantN || res.Folded != 3 {
		t.Fatalf("folded=%d fold-count=%d want 3 (invoke+respond+compose)", res.Folded, wantN)
	}
}

// TestExecutor_RootIsDeterministicAndLocked locks the concrete root for the fixed-key
// corpus, so a change to the composed pipeline that silently perturbs the committed
// root is caught (not just relative equality with the fold).
func TestExecutor_RootIsDeterministicAndLocked(t *testing.T) {
	const wantRoot = "0x186ddbfe65876d7fbb4f6d9c36f906cfaa856589ff44cf52d1e0089e49c747b7"
	cfg := params.OptimismTestConfig
	header := &types.Header{Number: big.NewInt(100), Time: 0}
	signer := types.MakeSigner(cfg, header.Number, header.Time)
	key := fixedKey(t)
	txs := workflowBlock(t, signer, key, cfg.ChainID)

	roots := make([]common.Hash, 2)
	for i := range roots {
		res, err := New(signer, cfg).ExecuteBlock(newState(t), header, txs)
		if err != nil {
			t.Fatal(err)
		}
		roots[i] = res.ReexecRoot
	}
	if roots[0] != roots[1] {
		t.Fatalf("non-deterministic root: %s vs %s", roots[0].Hex(), roots[1].Hex())
	}
	if roots[0].Hex() != wantRoot {
		t.Fatalf("LOCKED root changed (update only if the change is intended): got %s want %s", roots[0].Hex(), wantRoot)
	}
}

// TestExecutor_CrossBlockEvictionMatchesFold exercises the CROSS-BLOCK path the
// same-block tests never touch: a RESPOND alone in its block (empty in-block map) must
// resolve its parent INVOKE through the ring resolver, and the executor must reproduce
// the fraud gate's eviction behavior at the W-block boundary. This only holds because
// ExecuteBlock evicts (ProcessReexecStore) BEFORE folding — with the opposite ordering
// the boundary RESPOND would wrongly fold a parent the chain has evicted.
func TestExecutor_CrossBlockEvictionMatchesFold(t *testing.T) {
	cfg := params.OptimismTestConfig
	signer := types.MakeSigner(cfg, big.NewInt(100), 0)
	key := fixedKey(t)
	wf := common.HexToHash("0xCB")
	W := params.AGNT2ReexecWindow // 256
	const M = uint64(100)

	invoke, err := types.SignNewTx(key, signer, &types.InvokeTx{
		ChainID: cfg.ChainID, Nonce: 0, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
		Gas: 100000, WorkflowId: wf, StepId: 1, AgentRole: "worker", DepInvokeIds: []common.Hash{}, Payload: []byte("call"),
	})
	if err != nil {
		t.Fatal(err)
	}
	respond, err := types.SignNewTx(key, signer, &types.RespondTx{
		ChainID: cfg.ChainID, Nonce: 1, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
		Gas: 100000, WorkflowId: wf, StepId: 2, InvokeRef: invoke.Hash(), ResponsePayload: []byte("resp"), Status: 0,
	})
	if err != nil {
		t.Fatal(err)
	}

	// write the INVOKE at block M, then submit the RESPOND alone at respondBlock.
	foldedAt := func(respondBlock uint64) uint64 {
		sdb := newState(t)
		ex := New(signer, cfg)
		if _, err := ex.ExecuteBlock(sdb, &types.Header{Number: new(big.Int).SetUint64(M), Time: 0}, []*types.Transaction{invoke}); err != nil {
			t.Fatal(err)
		}
		res, err := ex.ExecuteBlock(sdb, &types.Header{Number: new(big.Int).SetUint64(respondBlock), Time: 0}, []*types.Transaction{respond})
		if err != nil {
			t.Fatal(err)
		}
		return res.Folded
	}

	// Parent resolvable at block M+W-1 (last block of the [M, M+W-1] window) => folds.
	if f := foldedAt(M + W - 1); f != 1 {
		t.Fatalf("in-window RESPOND (block %d) should resolve+fold via the ring, folded=%d want 1", M+W-1, f)
	}
	// Parent exactly W blocks old is evicted BEFORE the fold at block M+W => M6 skip.
	if f := foldedAt(M + W); f != 0 {
		t.Fatalf("boundary RESPOND (block %d) parent should be evicted (M6 skip), folded=%d want 0", M+W, f)
	}
}

// TestExecutor_TransitionTouchesExpectedKeyspaces asserts each op did the REAL state
// work its pipeline stage implies — so the composed-µs benchmark is timing genuine
// escrow/reputation/trie writes, not a no-op.
func TestExecutor_TransitionTouchesExpectedKeyspaces(t *testing.T) {
	cfg := params.OptimismTestConfig
	header := &types.Header{Number: big.NewInt(100), Time: 0}
	signer := types.MakeSigner(cfg, header.Number, header.Time)
	txs := workflowBlock(t, signer, fixedKey(t), cfg.ChainID)

	sdb := newState(t)
	res, err := New(signer, cfg).ExecuteBlock(sdb, header, txs)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Steps) != 3 {
		t.Fatalf("want 3 step metrics, got %d", len(res.Steps))
	}
	inv, resp, comp := res.Steps[0], res.Steps[1], res.Steps[2]
	// INVOKE: 2 writes (trie leaf + ttl), no balance moves.
	if inv.StateWrites != 2 || inv.BalanceMoves != 0 {
		t.Fatalf("INVOKE metrics=%+v want writes=2 balMoves=0", inv)
	}
	// RESPOND: 1 read (parent from ring) + 2 writes (trie + ttl).
	if resp.StateReads != 1 || resp.StateWrites != 2 {
		t.Fatalf("RESPOND metrics=%+v want reads=1 writes=2", resp)
	}
	// COMPOSE (fan-in 2): 2 balance moves; reads = 1 escrow + 2 rep = 3; writes = 1 escrow + 2 rep + 1 trie = 4.
	if comp.BalanceMoves != 2 || comp.StateReads != 3 || comp.StateWrites != 4 {
		t.Fatalf("COMPOSE metrics=%+v want balMoves=2 reads=3 writes=4", comp)
	}

	// The COMPOSE settlement actually credited the two synthetic agents.
	for i := 0; i < 2; i++ {
		ag := composeAgent(common.HexToHash("0xC0"), i)
		if sdb.GetBalance(ag).IsZero() {
			t.Fatalf("agent %d (%s) was not credited by COMPOSE settle", i, ag.Hex())
		}
	}
}

// TestExecutor_ComposeFanInScalesWrites: the COMPOSE settlement cost scales with the
// declared step count (fan-in) — the property the sub-linear/crossover economics and
// the scheduler's write-set both depend on.
func TestExecutor_ComposeFanInScalesWrites(t *testing.T) {
	cfg := params.OptimismTestConfig
	header := &types.Header{Number: big.NewInt(100), Time: 0}
	signer := types.MakeSigner(cfg, header.Number, header.Time)
	key := fixedKey(t)

	writesFor := func(stepCount uint8) int {
		compose, err := types.SignNewTx(key, signer, &types.ComposeTypedTx{
			ChainID: cfg.ChainID, Nonce: 0, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
			Gas: 400000, WorkflowId: common.HexToHash("0xC0"), StepCount: stepCount,
			StepWorkflowRoots: make([]common.Hash, stepCount), Payouts: make([]*big.Int, 0),
		})
		if err != nil {
			t.Fatal(err)
		}
		sdb := newState(t)
		ex := New(signer, cfg)
		ex.EnsureSystemAccounts(sdb)
		r, err := ex.ComposedStep(sdb, compose)
		if err != nil {
			t.Fatal(err)
		}
		return r.Metrics.StateWrites
	}
	// writes = 1 escrow + stepCount reputation + 1 trie leaf.
	if w2, w5 := writesFor(2), writesFor(5); w5-w2 != 3 {
		t.Fatalf("COMPOSE writes should grow 1 per fan-in step: fanIn2=%d fanIn5=%d (delta %d, want 3)", w2, w5, w5-w2)
	}
}
