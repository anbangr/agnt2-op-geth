package vm

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/holiman/uint256"
)

// Phase 6 review (Codex GATE FAIL #1) added these tests. They cover the
// dispatch boundary that earlier inline-only tests skipped:
//
//   1. evm.Call(0x0BC2, valid 1-step) — exactly stepCount logs land in
//      stateDB.Logs() after the call, with the right topic[0] / topic[1].
//   2. STATICCALL(0x0BC2) directly — returns revert byte 0x09, zero logs.
//   3. STATICCALL → CALL(0x0BC2) (nested-static bypass) — must ALSO
//      return 0x09 because evm.readOnly propagates through CALL frames.
//      This is the bug Codex caught: hardcoded readOnly=false in three
//      dispatch sites silently allowed a static parent's child CALL to
//      emit logs anyway. The fix passes evm.readOnly through.
//   4. Parent-frame REVERT after a successful AGNT2 call — the EVM journal
//      should drop the AddLog entries from the reverted frame.

// newTestEVM builds an EVM + StateDB suitable for dispatch tests. Uses
// the Optimism Jovian config so the AGNT2 precompile registry is active.
func newTestEVM(t *testing.T) (*EVM, *state.StateDB) {
	t.Helper()
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil), nil))
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	chainCfg := params.OptimismTestConfig
	blockCtx := BlockContext{
		CanTransfer: func(StateDB, common.Address, *uint256.Int) bool { return true },
		Transfer:    func(StateDB, common.Address, common.Address, *uint256.Int, *params.Rules) {},
		Coinbase:    common.Address{0x99},
		BlockNumber: big.NewInt(1),
		Time:        2_000_000_000, // post-Jovian timestamp
		GasLimit:    30_000_000,
		Difficulty:  big.NewInt(0),
		Random:      &common.Hash{}, // post-merge marker
		BaseFee:     big.NewInt(1_000_000_000),
	}
	txCtx := TxContext{Origin: common.Address{0x01}, GasPrice: uint256.NewInt(1)}
	evm := NewEVM(blockCtx, statedb, chainCfg, Config{})
	evm.SetTxContext(txCtx)
	// Sanity: the AGNT2 precompile must resolve.
	if _, ok := evm.precompile(AGNT2InteractionPrecompileAddress); !ok {
		t.Fatalf("0x0BC2 not in active precompile set under OptimismTestConfig — fork-rule mismatch")
	}
	return evm, statedb
}

// TestDispatch_Call_EmitsLogs proves the post-success hook actually runs
// stateDB.AddLog through the full evm.Call dispatch path — not just the
// in-process RunPrecompiledContract that earlier Phase 1 tests covered.
func TestDispatch_Call_EmitsLogs(t *testing.T) {
	evm, statedb := newTestEVM(t)
	caller := common.Address{0xCA, 0xFE}
	wfID := "dispatch-call-1"
	wfHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(wfHash, 3)
	input := makeInputWithLeaves(wfID, leaves)

	gas := params.AGNT2BaseGas + 3*params.AGNT2PerStepGas + 1_000_000
	ret, leftGas, err := evm.Call(caller, AGNT2InteractionPrecompileAddress, input, gas, uint256.NewInt(0))
	if err != nil {
		t.Fatalf("evm.Call failed: %v (ret=%x leftGas=%d)", err, ret, leftGas)
	}
	if ret != nil {
		t.Fatalf("expected empty return on success, got %x", ret)
	}

	logs := statedb.Logs()
	if len(logs) != 3 {
		t.Fatalf("expected 3 AGNT2 logs after evm.Call, got %d", len(logs))
	}
	for i, log := range logs {
		if log.Address != AGNT2InteractionPrecompileAddress {
			t.Errorf("log[%d] address = %s, want 0x0BC2", i, log.Address.Hex())
		}
		if len(log.Topics) != 2 {
			t.Errorf("log[%d] topics len = %d, want 2 (sig + WorkflowIDHash)", i, len(log.Topics))
			continue
		}
		if log.Topics[0] != agnt2LeafEventTopic0 {
			t.Errorf("log[%d] topic[0] = %x, want agnt2LeafEventTopic0 %x", i, log.Topics[0], agnt2LeafEventTopic0)
		}
		var wantWfHash common.Hash
		copy(wantWfHash[:], wfHash)
		if log.Topics[1] != wantWfHash {
			t.Errorf("log[%d] topic[1] = %x, want WorkflowIDHash %x", i, log.Topics[1], wantWfHash)
		}
	}
}

// TestDispatch_StaticCall_RejectsWithByte09 proves direct STATICCALL into
// 0x0BC2 returns the consensus-safety guard revert.
func TestDispatch_StaticCall_RejectsWithByte09(t *testing.T) {
	evm, statedb := newTestEVM(t)
	caller := common.Address{0xCA, 0xFE}
	wfID := "static-direct"
	wfHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(wfHash, 1)
	input := makeInputWithLeaves(wfID, leaves)

	gas := params.AGNT2BaseGas + 1*params.AGNT2PerStepGas + 1_000_000
	ret, _, err := evm.StaticCall(caller, AGNT2InteractionPrecompileAddress, input, gas)
	if err != ErrExecutionReverted {
		t.Fatalf("expected ErrExecutionReverted, got %v", err)
	}
	if len(ret) != 1 || ret[0] != revertStaticCall {
		t.Fatalf("expected revert byte 0x%02x, got %x", revertStaticCall, ret)
	}
	if got := len(statedb.Logs()); got != 0 {
		t.Fatalf("STATICCALL emitted %d logs (must be zero — consensus split)", got)
	}
}

// TestDispatch_NestedStaticCall_RejectsWithByte09 is the regression for
// Codex GATE FAIL #1: a CALL invoked from inside a STATICCALL frame must
// also be rejected, because evm.readOnly is true throughout the static
// frame even when the inner call is technically a CALL opcode. The fix
// in evm.go was to pass evm.readOnly (not hardcoded false) from the
// Call/CallCode/DelegateCall dispatch sites.
//
// We model this here by setting evm.readOnly = true before invoking
// evm.Call directly. The opCall path in instructions.go does the same:
// when the parent frame is static, it preserves evm.readOnly across the
// CALL into the child. If the dispatch site ignored evm.readOnly the way
// it did before this fix, this test would see 3 logs and a nil error —
// the consensus bug.
func TestDispatch_NestedStaticCall_RejectsWithByte09(t *testing.T) {
	evm, statedb := newTestEVM(t)
	evm.readOnly = true // simulate being inside a STATICCALL frame
	caller := common.Address{0xCA, 0xFE}
	wfID := "static-nested"
	wfHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(wfHash, 3)
	input := makeInputWithLeaves(wfID, leaves)

	gas := params.AGNT2BaseGas + 3*params.AGNT2PerStepGas + 1_000_000
	ret, _, err := evm.Call(caller, AGNT2InteractionPrecompileAddress, input, gas, uint256.NewInt(0))
	if err != ErrExecutionReverted {
		t.Fatalf("expected ErrExecutionReverted under nested-static CALL, got %v", err)
	}
	if len(ret) != 1 || ret[0] != revertStaticCall {
		t.Fatalf("expected revert byte 0x%02x under nested-static CALL, got %x", revertStaticCall, ret)
	}
	if got := len(statedb.Logs()); got != 0 {
		t.Fatalf("nested-static CALL emitted %d logs (consensus bug regression — see Codex Phase 6 review #1)", got)
	}
}

// TestDispatch_RevertDropsLogs proves that when a parent frame REVERTs
// after a successful AGNT2 call, the EVM journal drops the AddLog
// entries from the reverted snapshot. We emulate this with explicit
// Snapshot/RevertToSnapshot since opCall's revert path does the same
// thing internally.
func TestDispatch_RevertDropsLogs(t *testing.T) {
	evm, statedb := newTestEVM(t)
	caller := common.Address{0xCA, 0xFE}
	wfID := "revert-drops-logs"
	wfHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(wfHash, 2)
	input := makeInputWithLeaves(wfID, leaves)

	snap := statedb.Snapshot()

	gas := params.AGNT2BaseGas + 2*params.AGNT2PerStepGas + 1_000_000
	if _, _, err := evm.Call(caller, AGNT2InteractionPrecompileAddress, input, gas, uint256.NewInt(0)); err != nil {
		t.Fatalf("inner evm.Call failed: %v", err)
	}
	if got := len(statedb.Logs()); got != 2 {
		t.Fatalf("pre-revert: expected 2 logs, got %d", got)
	}

	// Parent frame REVERTs — the EVM journal restores the snapshot,
	// which drops the AddLog entries.
	statedb.RevertToSnapshot(snap)

	if got := len(statedb.Logs()); got != 0 {
		t.Fatalf("post-revert: expected 0 logs (journal drops AddLog), got %d", got)
	}
}

// silence unused-import lint when the build excludes specific helpers.
var _ = tracing.BalanceChangeTouchAccount
