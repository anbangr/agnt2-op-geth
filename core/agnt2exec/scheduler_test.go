package agnt2exec

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// genWorkload builds N independent workflows, each INVOKE -> RESPOND -> COMPOSE(fanIn),
// all from one key with sequential nonces. Distinct workflow ids; the COMPOSE settled
// agents are drawn from the AgentPoolSize pool (so a small pool shares agents across
// workflows). If linkInvokes, each workflow's INVOKE declares a DepInvokeIds edge on
// the previous workflow's INVOKE — exercising the INVOKE->INVOKE DAG edge.
func genWorkload(t *testing.T, signer types.Signer, key *ecdsa.PrivateKey, cid *big.Int, n int, fanIn uint8, linkInvokes bool) []*types.Transaction {
	t.Helper()
	var txs []*types.Transaction
	nonce := uint64(0)
	mk := func(inner types.TxData) *types.Transaction {
		tx, err := types.SignNewTx(key, signer, inner)
		if err != nil {
			t.Fatal(err)
		}
		return tx
	}
	var prevInv common.Hash
	for w := 0; w < n; w++ {
		wf := common.BigToHash(big.NewInt(int64(w + 1)))
		deps := []common.Hash{}
		if linkInvokes && w > 0 {
			deps = []common.Hash{prevInv}
		}
		inv := mk(&types.InvokeTx{ChainID: cid, Nonce: nonce, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
			Gas: 100000, WorkflowId: wf, StepId: 1, AgentRole: "worker", DepInvokeIds: deps, Payload: []byte("call")})
		nonce++
		prevInv = inv.Hash()
		resp := mk(&types.RespondTx{ChainID: cid, Nonce: nonce, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
			Gas: 100000, WorkflowId: wf, StepId: 2, InvokeRef: inv.Hash(), ResponsePayload: []byte("resp"), Status: 0})
		nonce++
		comp := mk(&types.ComposeTypedTx{ChainID: cid, Nonce: nonce, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
			Gas: 800000, WorkflowId: wf, StepCount: fanIn, StepWorkflowRoots: make([]common.Hash, fanIn), Payouts: []*big.Int{}})
		nonce++
		txs = append(txs, inv, resp, comp)
	}
	return txs
}

// TestSchedule_DepsSubsetOfConflicts is the SOUNDNESS check: every declared dependency
// edge — both RESPOND->InvokeRef AND INVOKE->DepInvokeIds — is a conflict, so the
// scheduler never drops a real dependency. Exercised over a workload containing BOTH
// edge kinds (the earlier version only had RESPOND edges).
func TestSchedule_DepsSubsetOfConflicts(t *testing.T) {
	cfg := params.OptimismTestConfig
	signer := types.MakeSigner(cfg, big.NewInt(1), 0)
	txs := genWorkload(t, signer, fixedKey(t), cfg.ChainID, 50, 3, true /*linkInvokes*/)

	rw := make([]RWSet, len(txs))
	idx := map[common.Hash]int{}
	for i, tx := range txs {
		rw[i] = DeclareRW(tx, signer)
		idx[tx.Hash()] = i
	}
	respEdges, invEdges := 0, 0
	for i, tx := range txs {
		for _, dep := range tx.Agnt2Dependencies() {
			j, ok := idx[dep]
			if !ok {
				continue
			}
			// declared deps must conflict under BOTH the commutativity-aware and the
			// conservative relation (a dropped dep would be unsound for any executor).
			if !Conflicts(rw[i], rw[j]) || !ConflictsConservative(rw[i], rw[j]) {
				t.Fatalf("SOUNDNESS VIOLATED: dep edge op%d->op%d (type %d) is not a conflict", j, i, tx.Type())
			}
			if tx.Type() == types.InvokeTxType {
				invEdges++
			} else {
				respEdges++
			}
		}
	}
	if respEdges == 0 || invEdges == 0 {
		t.Fatalf("workload must exercise BOTH edge kinds: respEdges=%d invEdges=%d", respEdges, invEdges)
	}
}

// TestSchedule_WavesAreConflictFree: no two ops in the same wave conflict under the
// commutativity-aware relation that built it, and the schedule is deterministic.
func TestSchedule_WavesAreConflictFree(t *testing.T) {
	cfg := params.OptimismTestConfig
	signer := types.MakeSigner(cfg, big.NewInt(1), 0)
	txs := genWorkload(t, signer, fixedKey(t), cfg.ChainID, 40, 4, false)
	rw := make([]RWSet, len(txs))
	for i, tx := range txs {
		rw[i] = DeclareRW(tx, signer)
	}
	s := BuildSchedule(txs, signer)
	for w, wave := range s.Waves {
		for a := 0; a < len(wave); a++ {
			for b := a + 1; b < len(wave); b++ {
				if Conflicts(rw[wave[a]], rw[wave[b]]) {
					t.Fatalf("wave %d has conflicting ops %d and %d", w, wave[a], wave[b])
				}
			}
		}
	}
	s2 := BuildSchedule(txs, signer)
	for i := range s.WaveOf {
		if s.WaveOf[i] != s2.WaveOf[i] {
			t.Fatalf("schedule not deterministic at op %d", i)
		}
	}
}

// TestSchedule_ThreeModelsAndCommutativity locks the corrected relationships:
//   - topology-only over-states parallelism (misses ordered leaf/ring edges);
//   - conservative ≤ commutativity-aware ≤ topology;
//   - concentrating the agent pool COLLAPSES the conservative schedule (it serializes
//     commutative credits) but leaves the commutativity-aware schedule INVARIANT
//     (bal:/rep: credits are commutative and never read here) — i.e. the settlement
//     collapse is an artifact of naive conflict detection, not inherent to settlement.
func TestSchedule_ThreeModelsAndCommutativity(t *testing.T) {
	cfg := params.OptimismTestConfig
	signer := types.MakeSigner(cfg, big.NewInt(1), 0)
	txs := genWorkload(t, signer, fixedKey(t), cfg.ChainID, 100, 3, false)
	top := BuildTopologySchedule(txs, signer)

	saved := AgentPoolSize
	defer func() { AgentPoolSize = saved }()

	AgentPoolSize = 1 << 40
	caBig := BuildSchedule(txs, signer)
	conBig := BuildScheduleConservative(txs, signer)
	if caBig.MaxParallelism() > top.MaxParallelism() {
		t.Fatalf("commutativity-aware (%.1f) must be <= topology (%.1f)", caBig.MaxParallelism(), top.MaxParallelism())
	}
	if conBig.MaxParallelism() > caBig.MaxParallelism() {
		t.Fatalf("conservative (%.1f) must be <= commutativity-aware (%.1f)", conBig.MaxParallelism(), caBig.MaxParallelism())
	}

	AgentPoolSize = 8
	caSmall := BuildSchedule(txs, signer)
	conSmall := BuildScheduleConservative(txs, signer)
	if conSmall.MaxParallelism() >= conBig.MaxParallelism() {
		t.Fatalf("conservative should COLLAPSE at a small agent pool: small=%.2f big=%.2f", conSmall.MaxParallelism(), conBig.MaxParallelism())
	}
	if caSmall.MaxParallelism() != caBig.MaxParallelism() {
		t.Fatalf("commutativity-aware should be INVARIANT to agent pool (commutative credits): small=%.2f big=%.2f", caSmall.MaxParallelism(), caBig.MaxParallelism())
	}
}
