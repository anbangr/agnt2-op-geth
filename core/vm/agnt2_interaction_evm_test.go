package vm

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// Phase 1 — these tests prove the AGNT2 precompile is reachable via the
// op-geth precompile dispatch path (RunPrecompiledContract). They do NOT
// stand up a full EVM with state — that's reserved for Phase 6 (persistent
// MMR state) and Phase 7 (block-header interaction-root). The dispatch
// surface is what Phase 1 wires up; the state is what Phase 6+ wires up.

func TestAgnt2Registry_AddressLockedAt0x0BC2(t *testing.T) {
	expected := common.BytesToAddress([]byte{0x0B, 0xC2})
	if AGNT2InteractionPrecompileAddress != expected {
		t.Fatalf("AGNT2 precompile address drifted: got %s, want %s",
			AGNT2InteractionPrecompileAddress.Hex(), expected.Hex())
	}
	// Defense-in-depth: confirm the byte layout matches ADR 002 §Calldata Format
	// exactly. Hex() applies EIP-55 checksum casing so we compare raw bytes.
	want := [20]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0B, 0xC2}
	if [20]byte(AGNT2InteractionPrecompileAddress) != want {
		t.Fatalf("ADR 002 lock broken: %x", AGNT2InteractionPrecompileAddress)
	}
}

func TestAgnt2Registry_RegisteredInIsthmusAndJovian(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  PrecompiledContracts
	}{
		{"Isthmus", PrecompiledContractsIsthmus},
		{"Jovian", PrecompiledContractsJovian},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p, ok := tc.set[AGNT2InteractionPrecompileAddress]
			if !ok {
				t.Fatalf("0x0BC2 not registered in %s precompile set", tc.name)
			}
			if _, isAGNT2 := p.(*agnt2Interaction); !isAGNT2 {
				t.Fatalf("0x0BC2 in %s set resolves to %T, want *agnt2Interaction", tc.name, p)
			}
		})
	}
}

func TestAgnt2Registry_NoCollisionWithUpstreamPrecompiles(t *testing.T) {
	// 0x0BC2 must not collide with any upstream Optimism or Ethereum precompile
	// in the pre-AGNT2 fork tables. If upstream ever lands a precompile at
	// 0x0BC2 or 0x0B/0xBC2 prefix-collides with one, this test fires before
	// the silent override does damage.
	//
	// PrecompiledContractsBLS aliases Prague and PrecompiledContractsVerkle
	// aliases Berlin, so those are covered transitively.
	conflictSets := map[string]PrecompiledContracts{
		"Cancun":     PrecompiledContractsCancun,
		"Prague":     PrecompiledContractsPrague,
		"Osaka":      PrecompiledContractsOsaka,
		"Fjord":      PrecompiledContractsFjord,
		"Granite":    PrecompiledContractsGranite,
		"Homestead":  PrecompiledContractsHomestead,
		"Byzantium":  PrecompiledContractsByzantium,
		"Istanbul":   PrecompiledContractsIstanbul,
		"Berlin":     PrecompiledContractsBerlin,
		"P256Verify": PrecompiledContractsP256Verify,
	}
	for name, set := range conflictSets {
		if _, exists := set[AGNT2InteractionPrecompileAddress]; exists {
			t.Fatalf("collision: 0x0BC2 already registered in %s set (upstream change?)", name)
		}
	}
}

// TestAgnt2Registry_AddressSliceIncludes0x0BC2 proves that contracts.go's
// init() iteration over the precompile maps observed our 0x0BC2 mutation
// (init order: agnt2_*.go runs before contracts.go alphabetically). Without
// this, ActivePrecompiles() callers (tracing, debug RPC) would not list
// the AGNT2 precompile as known.
func TestAgnt2Registry_AddressSliceIncludes0x0BC2(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addresses []common.Address
	}{
		{"Isthmus", PrecompiledAddressesIsthmus},
		{"Jovian", PrecompiledAddressesJovian},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			found := false
			for _, addr := range tc.addresses {
				if addr == AGNT2InteractionPrecompileAddress {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("PrecompiledAddresses%s slice missing 0x0BC2 — init() ordering broken", tc.name)
			}
		})
	}
}

// TestAgnt2Dispatch_HappyPath_1Step exercises the full RunPrecompiledContract
// path that op-geth uses when an EVM CALL targets a precompile address.
// Parameterized over both Isthmus and Jovian precompile sets to confirm
// dispatch works on both Optimism fork-tags AGNT2 supports.
//
// Asserts: (a) the precompile resolves via the registry, (b) gas is charged
// at AGNT2BaseGas + N*AGNT2PerStepGas exactly, (c) returnData is empty on
// success, (d) no err.
func TestAgnt2Dispatch_HappyPath_1Step(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  PrecompiledContracts
	}{
		{"Isthmus", PrecompiledContractsIsthmus},
		{"Jovian", PrecompiledContractsJovian},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(globalAgnt2EventStore.reset)
			globalAgnt2EventStore.reset()
			t.Cleanup(globalAgnt2RootStore.reset)

			p, ok := tc.set[AGNT2InteractionPrecompileAddress]
			if !ok {
				t.Fatalf("0x0BC2 not registered in %s", tc.name)
			}

			wfID := "evm-dispatch-happy-1"
			expectedHash := crypto.Keccak256([]byte(wfID))
			leaves := makeChainedLeaves(expectedHash, 1)
			input := makeInputWithLeaves(wfID, leaves)

			expectedGas := params.AGNT2BaseGas + 1*params.AGNT2PerStepGas
			suppliedGas := expectedGas + 1_000_000

			ret, remainingGas, err := RunPrecompiledContract(nil, p, AGNT2InteractionPrecompileAddress, input, suppliedGas, nil)
			if err != nil {
				t.Fatalf("dispatch failed: %v", err)
			}
			if ret != nil {
				t.Fatalf("expected empty return data on success, got %x", ret)
			}
			if got := suppliedGas - remainingGas; got != expectedGas {
				t.Fatalf("gas charged %d, want %d (= AGNT2BaseGas %d + 1*AGNT2PerStepGas %d)",
					got, expectedGas, params.AGNT2BaseGas, params.AGNT2PerStepGas)
			}
			if got := len(LastEmittedEvents()); got != 1 {
				t.Fatalf("expected 1 leaf event committed via dispatch, got %d", got)
			}
		})
	}
}

// TestAgnt2Dispatch_RevertOnBadVersion proves that a malformed call
// produces ErrExecutionReverted (NOT a custom AGNT2 sentinel) at the
// dispatch boundary. Direct equality against ErrExecutionReverted is what
// op-geth's evm.go:331 checks to decide gas-refund-on-revert vs all-gas-
// consumed; any other error from a precompile triggers the all-gas branch.
//
// Asserts: (a) err IS the ErrExecutionReverted sentinel (direct equality,
// not errors.Is — that's what the EVM uses), (b) the revert byte is the
// first byte of returnData (ADR 002 §Revert Error Codes contract).
func TestAgnt2Dispatch_RevertOnBadVersion(t *testing.T) {
	t.Cleanup(globalAgnt2EventStore.reset)
	globalAgnt2EventStore.reset()
	t.Cleanup(globalAgnt2RootStore.reset)

	p := PrecompiledContractsJovian[AGNT2InteractionPrecompileAddress]
	badInput := makeInput(0x01, 1, 160) // version 0x01 (must be 0x00)

	ret, remainingGas, err := RunPrecompiledContract(nil, p, AGNT2InteractionPrecompileAddress, badInput, 1_000_000, nil)
	if err != ErrExecutionReverted {
		t.Fatalf("Phase 2 contract: expected vm.ErrExecutionReverted (direct ==), got %v", err)
	}
	if len(ret) != 1 || ret[0] != revertInvalidVersion {
		t.Fatalf("expected revert byte 0x%02x, got %x", revertInvalidVersion, ret)
	}
	// Gas accounting on revert: caller's remainingGas is preserved minus the
	// already-charged RequiredGas (the EVM refunds whatever didn't reach Run's
	// internal work). Bad-version is a syntactic check, so RequiredGas returns
	// base gas only — this assertion proves that's what the dispatch wrapper
	// actually billed (NOT all-gas-consumed).
	expectedCharged := p.RequiredGas(badInput)
	if got := uint64(1_000_000) - remainingGas; got != expectedCharged {
		t.Fatalf("revert gas charged %d, want %d (RequiredGas only — no all-gas-consumed)", got, expectedCharged)
	}
}

// TestAgnt2Dispatch_OutOfGas asserts the dispatch wrapper returns ErrOutOfGas
// when the caller's supplied gas is below RequiredGas — without ever
// invoking Run. This pins the gas-grief mitigation: a gas-starved caller
// pays nothing at the precompile body and sees the standard EVM out-of-gas
// signal.
func TestAgnt2Dispatch_OutOfGas(t *testing.T) {
	t.Cleanup(globalAgnt2EventStore.reset)
	globalAgnt2EventStore.reset()
	t.Cleanup(globalAgnt2RootStore.reset)

	p := PrecompiledContractsJovian[AGNT2InteractionPrecompileAddress]
	wfID := "evm-dispatch-oog"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 3)
	input := makeInputWithLeaves(wfID, leaves)

	required := params.AGNT2BaseGas + 3*params.AGNT2PerStepGas
	starved := required - 1

	_, _, err := RunPrecompiledContract(nil, p, AGNT2InteractionPrecompileAddress, input, starved, nil)
	if !errors.Is(err, ErrOutOfGas) {
		t.Fatalf("expected ErrOutOfGas, got %v", err)
	}
	// Run() must NOT have executed — store stays empty.
	if got := len(LastEmittedEvents()); got != 0 {
		t.Fatalf("dispatch ran Run() despite OOG (store has %d events)", got)
	}
}
