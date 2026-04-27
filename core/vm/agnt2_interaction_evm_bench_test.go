package vm

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// Phase 8 — F5 end-to-end EVM-dispatch microbenchmark.
//
// The function-body benches (BenchmarkAgnt2Run / BenchmarkAgnt2Noop in
// agnt2_interaction_bench_test.go) call PrecompiledContract.Run() directly.
// They miss the four-stage dispatch the EVM actually walks when a CALL
// targets the precompile address: precompile lookup, snapshot, gas refund
// machinery, and the Phase 6 evmAGNT2PostHook (log emission for AGNT2,
// no-op for the control). The paper's F5 figure needs the full dispatch
// cost so the overhead delta reflects what a real transaction sees, not
// just the precompile body.
//
// Bench name suffix `EVM` so extract-f5-csv.sh's regex stays additive
// (matches BenchmarkAgnt2(Run|Noop)(EVM)?). The "modified" path goes to
// 0x0BC2 (AGNT2 — registered post-hook fires, logs emitted via AddLog);
// the "unmodified" control path goes to 0x0001 (ecrecover — same dispatch
// surface, but no post-hook applies because the addr filter at the top of
// evmAGNT2PostHook returns ret/gas/err unchanged).
//
// Controlled variables (per /codex review): same calldata bytes (so
// dispatch + memory + gas-deduction branches see equal-sized arguments),
// same supplied gas (10M, well above either precompile's RequiredGas),
// same fork context (Optimism Jovian — 0x0BC2 registered, AGNT2PerStepGas
// includes the Phase 6 LOG cost), same caller address.
//
// State growth: AGNT2 dispatch calls AddLog N×stepCount times across b.N
// iterations. Without resetting, the StateDB.logs slice would grow O(N×b.N)
// and skew later iterations. Bench loop snapshots before each call and
// reverts after — RevertToSnapshot drops journal-tracked log entries, so
// each iteration sees a fresh log list. The control bench mirrors the
// snapshot/revert pattern so dispatch overhead is comparable.

// agnt2BenchEVM is a one-shot fixture: a fresh StateDB + EVM tied to
// OptimismTestConfig (Jovian active, so 0x0BC2 is in the precompile set).
// Built once per b.Run subtest so bench setup cost is excluded from the
// reported ns/op.
type agnt2BenchEVM struct {
	evm     *EVM
	statedb *state.StateDB
	caller  common.Address
}

func newAgnt2BenchEVM(b *testing.B) *agnt2BenchEVM {
	b.Helper()
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		b.Fatalf("statedb init: %v", err)
	}
	caller := common.BytesToAddress([]byte("agnt2-f5-bench-caller"))
	statedb.CreateAccount(caller)
	statedb.AddBalance(caller, uint256.NewInt(1), 0)

	// Random must be non-nil so chainRules.Rules() flips isMerge true; without
	// it IsOptimismJovian is false (gated on `isMerge && c.IsJovian(time)`)
	// and 0x0BC2 falls back to a non-AGNT2 precompile set.
	random := common.Hash{}
	vmctx := BlockContext{
		CanTransfer: func(StateDB, common.Address, *uint256.Int) bool { return true },
		Transfer:    func(StateDB, common.Address, common.Address, *uint256.Int, *params.Rules) {},
		BlockNumber: big.NewInt(1),
		Time:        1,
		Random:      &random,
	}
	evm := NewEVM(vmctx, statedb, params.OptimismTestConfig, Config{})

	if _, ok := evm.precompile(AGNT2InteractionPrecompileAddress); !ok {
		b.Fatalf("AGNT2 precompile not registered for OptimismTestConfig — Jovian time setup broke")
	}
	if _, ok := evm.precompile(common.BytesToAddress([]byte{0x01})); !ok {
		b.Fatalf("ecrecover not registered — bench control path is invalid")
	}
	return &agnt2BenchEVM{evm: evm, statedb: statedb, caller: caller}
}

// BenchmarkAgnt2RunEVM measures the AGNT2 precompile via the full EVM
// dispatch path (evm.Call → RunPrecompiledContract → evmAGNT2PostHook
// → stateDB.AddLog). Reported ns/op is the per-call cost the paper's F5
// figure is supposed to reflect, not just the function body.
//
// gas supplied (10M) is well above AGNT2BaseGas + 100*AGNT2PerStepGas
// (461_500 for the largest case) so the inner OOG branch never fires.
func BenchmarkAgnt2RunEVM(b *testing.B) {
	cases := []struct {
		name  string
		steps uint32
	}{
		{"1step", 1},
		{"3step", 3},
		{"5step", 5},
		{"100step", 100},
	}
	for _, tc := range cases {
		tc := tc
		b.Run(tc.name, func(b *testing.B) {
			fx := newAgnt2BenchEVM(b)
			input := benchInputForSteps(b, tc.steps)
			value := uint256.NewInt(0)
			b.SetBytes(int64(len(input)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				snap := fx.statedb.Snapshot()
				_, _, err := fx.evm.Call(fx.caller, AGNT2InteractionPrecompileAddress, input, 10_000_000, value)
				if err != nil {
					b.Fatalf("evm.Call(0x0BC2) failed: %v", err)
				}
				fx.statedb.RevertToSnapshot(snap)
			}
		})
	}
}

// BenchmarkAgnt2NoopEVM is the F5 dispatch-path control: the same evm.Call
// invocation against ecrecover (0x0001) with the AGNT2 calldata as stub
// input. ecrecover's body returns nil/nil for malformed signatures, so the
// call succeeds via the same dispatch path AGNT2 uses but exercises no
// AGNT2-specific work. The delta isolates AGNT2 protocol overhead at the
// EVM-dispatch layer.
//
// Why ecrecover and not a synthetic noop precompile: the goal is to compare
// against an UNMODIFIED op-geth precompile registry. Registering a noop at
// a free address would mutate the registry and defeat the purpose of the
// modified-vs-unmodified comparison the plan calls for.
func BenchmarkAgnt2NoopEVM(b *testing.B) {
	controlAddr := common.BytesToAddress([]byte{0x01}) // ecrecover
	cases := []struct {
		name  string
		steps uint32
	}{
		{"1step", 1},
		{"3step", 3},
		{"5step", 5},
		{"100step", 100},
	}
	for _, tc := range cases {
		tc := tc
		b.Run(tc.name, func(b *testing.B) {
			fx := newAgnt2BenchEVM(b)
			input := benchInputForSteps(b, tc.steps)
			value := uint256.NewInt(0)
			b.SetBytes(int64(len(input)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				snap := fx.statedb.Snapshot()
				_, _, err := fx.evm.Call(fx.caller, controlAddr, input, 10_000_000, value)
				if err != nil {
					b.Fatalf("evm.Call(ecrecover) failed: %v", err)
				}
				fx.statedb.RevertToSnapshot(snap)
			}
		})
	}
}
