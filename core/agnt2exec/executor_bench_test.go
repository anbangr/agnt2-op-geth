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

// BenchmarkSenderRecovery measures ECDSA sender recovery in ISOLATION via
// signer.Sender (which, unlike types.Sender, does NOT cache on tx.from). This is the
// once-per-tx admission cost that BenchmarkComposedStep deliberately does NOT re-pay
// per iteration (types.Sender is a cache hit after the first touch, exactly as in
// production where a tx's sender is recovered once at mempool admission). Reported so
// the composed-µs numbers are read honestly: recovery is a separate, dominant,
// once-per-tx line item — not part of the per-op EXECUTION cost.
func BenchmarkSenderRecovery(b *testing.B) {
	cfg := params.OptimismTestConfig
	signer := types.MakeSigner(cfg, big.NewInt(100), 0)
	tx := benchInvoke(b, signer, mustKey(b), cfg.ChainID)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := signer.Sender(tx); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/1000.0, "us/recover")
}

// BenchmarkComposedStep measures per-op EXECUTION-time composed-µs/op for the full
// transition pipeline, against the paper's 5–10 µs/op budget. IMPORTANT: this is
// execution-time with the sender already recovered (types.Sender caches on tx.from
// after the first touch, so iterations 2..N are cache hits — matching production,
// where recovery happens once at admission, NOT per block execution). The once-per-tx
// ECDSA recovery cost (~30 µs, see BenchmarkSenderRecovery) is therefore a SEPARATE
// line item and is not included in these per-op numbers. Per the F5-bench discipline,
// each iteration is wrapped in Snapshot/RevertToSnapshot so the StateDB journal does
// not grow O(writes·b.N) and skew late iterations.
//
// Run: go test ./core/agnt2exec/ -run x -bench BenchmarkComposedStep -benchmem
// Read µs/op = ns-per-op / 1000; compare to 5–10 µs (execution) and add ~30 µs for the
// once-per-tx recovery if a full first-touch cost is wanted.
func BenchmarkComposedStep(b *testing.B) {
	cfg := params.OptimismTestConfig
	signer := types.MakeSigner(cfg, big.NewInt(100), 0)
	k := mustKey(b)

	cases := []struct {
		name string
		tx   *types.Transaction
	}{
		{"invoke", benchInvoke(b, signer, k, cfg.ChainID)},
		{"respond", benchRespond(b, signer, k, cfg.ChainID)},
		{"compose_fanin_1", benchCompose(b, signer, k, cfg.ChainID, 1)},
		{"compose_fanin_3", benchCompose(b, signer, k, cfg.ChainID, 3)},
		{"compose_fanin_10", benchCompose(b, signer, k, cfg.ChainID, 10)},
		{"compose_fanin_50", benchCompose(b, signer, k, cfg.ChainID, 50)},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			sdb := newBenchState(b)
			exec := New(signer, cfg)
			exec.EnsureSystemAccounts(sdb)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				snap := sdb.Snapshot()
				if _, err := exec.ComposedStep(sdb, c.tx); err != nil {
					b.Fatal(err)
				}
				sdb.RevertToSnapshot(snap)
			}
			b.StopTimer()
			// composed µs/op vs the 5–10 µs budget — reported, never asserted (the
			// falsification is honest: if it exceeds 10 µs, that IS the finding).
			usPerOp := float64(b.Elapsed().Nanoseconds()) / float64(b.N) / 1000.0
			b.ReportMetric(usPerOp, "us/op")
			b.ReportMetric(10.0, "budget_us")
		})
	}
}

// BenchmarkExecuteBlock measures the whole-block path (composed steps + the delegated
// fold + ring write) amortized per op, to size the block-production cost that includes
// the fraud-root commitment.
func BenchmarkExecuteBlock(b *testing.B) {
	cfg := params.OptimismTestConfig
	signer := types.MakeSigner(cfg, big.NewInt(100), 0)
	k := mustKey(b)
	header := &types.Header{Number: big.NewInt(100), Time: 0}
	txs := workflowBlockB(b, signer, k, cfg.ChainID)
	exec := New(signer, cfg)
	sdb := newBenchState(b) // built ONCE, outside the timer; per-iter snapshot/revert
	exec.EnsureSystemAccounts(sdb)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		snap := sdb.Snapshot()
		if _, err := exec.ExecuteBlock(sdb, header, txs); err != nil {
			b.Fatal(err)
		}
		sdb.RevertToSnapshot(snap)
	}
	b.StopTimer()
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(txs))/1000.0, "us/op")
}

// --- bench helpers ---

func newBenchState(b *testing.B) *state.StateDB {
	b.Helper()
	sdb, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		b.Fatal(err)
	}
	return sdb
}

func mustKey(b *testing.B) *ecdsa.PrivateKey {
	b.Helper()
	k, err := crypto.HexToECDSA(fixedKeyHex)
	if err != nil {
		b.Fatal(err)
	}
	return k
}

func benchInvoke(b *testing.B, signer types.Signer, key *ecdsa.PrivateKey, cid *big.Int) *types.Transaction {
	tx, err := types.SignNewTx(key, signer, &types.InvokeTx{
		ChainID: cid, Nonce: 0, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
		Gas: 100000, WorkflowId: common.HexToHash("0xC0"), StepId: 1, AgentRole: "worker",
		DepInvokeIds: []common.Hash{}, Payload: []byte("call"),
	})
	if err != nil {
		b.Fatal(err)
	}
	return tx
}

func benchRespond(b *testing.B, signer types.Signer, key *ecdsa.PrivateKey, cid *big.Int) *types.Transaction {
	tx, err := types.SignNewTx(key, signer, &types.RespondTx{
		ChainID: cid, Nonce: 1, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
		Gas: 100000, WorkflowId: common.HexToHash("0xC0"), StepId: 2,
		InvokeRef: common.HexToHash("0xdead"), ResponsePayload: []byte("resp"), Status: 0,
	})
	if err != nil {
		b.Fatal(err)
	}
	return tx
}

func benchCompose(b *testing.B, signer types.Signer, key *ecdsa.PrivateKey, cid *big.Int, fanIn uint8) *types.Transaction {
	tx, err := types.SignNewTx(key, signer, &types.ComposeTypedTx{
		ChainID: cid, Nonce: 2, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
		Gas: 800000, WorkflowId: common.HexToHash("0xC0"), StepCount: fanIn,
		StepWorkflowRoots: make([]common.Hash, fanIn), Payouts: []*big.Int{},
	})
	if err != nil {
		b.Fatal(err)
	}
	return tx
}

func workflowBlockB(b *testing.B, signer types.Signer, key *ecdsa.PrivateKey, cid *big.Int) []*types.Transaction {
	inv := benchInvoke(b, signer, key, cid)
	resp, err := types.SignNewTx(key, signer, &types.RespondTx{
		ChainID: cid, Nonce: 1, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
		Gas: 100000, WorkflowId: common.HexToHash("0xC0"), StepId: 2, InvokeRef: inv.Hash(),
		ResponsePayload: []byte("resp"), Status: 0,
	})
	if err != nil {
		b.Fatal(err)
	}
	comp := benchCompose(b, signer, key, cid, 2)
	return []*types.Transaction{inv, resp, comp}
}
