package vm

import (
	"bytes"
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// AGNT2InteractionPrecompileAddress is the EVM address that dispatches to
// agnt2Interaction.Run. Locked by ADR 002 §Calldata Format. Registered into
// the active Optimism precompile sets via init() below — every binary built
// from this fork dispatches 0x0BC2 to the AGNT2 precompile regardless of
// which Optimism fork-tag the chain rules report (Isthmus or Jovian),
// because AGNT2 is a fork of those Optimism stacks, not a separate
// timestamp-gated activation.
var AGNT2InteractionPrecompileAddress = common.BytesToAddress([]byte{0x0B, 0xC2})

// init registers the AGNT2 interaction precompile into the active Optimism
// precompile dispatch tables. Mutating the maps here (instead of editing
// the table literals in contracts.go) keeps the AGNT2 fork's diff surface
// small and trivially survives upstream merges that touch contracts.go.
//
// Both Isthmus and Jovian get the registration so AGNT2 chains rolling
// either fork-tag dispatch correctly. Pre-Isthmus tables (Granite, Fjord,
// etc.) are intentionally untouched: AGNT2 requires the Isthmus-or-later
// withdrawal-root semantics to wire the interaction-root field cleanly in
// Week 11 Phase 7.
func init() {
	PrecompiledContractsIsthmus[AGNT2InteractionPrecompileAddress] = &agnt2Interaction{}
	PrecompiledContractsJovian[AGNT2InteractionPrecompileAddress] = &agnt2Interaction{}
}

// Run() now returns vm.ErrExecutionReverted directly (Week 11 Phase 2). The
// EVM at evm.go:331 uses `err == ErrExecutionReverted` direct equality (not
// errors.Is) to decide between gas-refund-on-revert and all-gas-consumed —
// any wrapping or substitution would silently flip AGNT2 reverts back to
// "all gas consumed" and break the documented ADR 002 §Revert Error Codes
// contract that callers see the byte payload as EVM return data with their
// remaining gas refunded.
//
// ErrAGNT2Reverted (the prior internal sentinel) is removed; tests now
// assert against ErrExecutionReverted directly.

// Revert codes returned alongside ErrExecutionReverted. Order is locked by ADR 002
// and the on-chain decoder; renumbering is a breaking change.
const (
	revertInvalidVersion          byte = 0x01 // byte 0 is not 0x00
	revertMalformedCalldata       byte = 0x02 // total length is inconsistent with step_count
	revertStepOverflow            byte = 0x03 // step_count * 160 exceeds the calldata size limit
	revertTrieWriteFailed         byte = 0x04 // MMR leaf write failed (Week 10 only)
	revertNotImplemented          byte = 0x05 // unused — retired by Phase 5
	revertWorkflowIDInvalid       byte = 0x06 // workflow_id parsing failed (offset, length, padding, range)
	revertWorkflowBindingMismatch byte = 0x07 // leaf.workflowIdHash != keccak256(workflow_id)
	revertLeafChainBroken         byte = 0x08 // leaf[i].prevLeafHash != leafHash(leaf[i-1])
)

const (
	agnt2LeafSize uint64 = 160
	// maxSafeLeafCount = floor((2^32 - 1) / 160) = 26_843_545.
	// Pinned as an explicit literal (not a derivation) so a future change to
	// agnt2LeafSize can't silently shift the bound and mask a regression in
	// TestMaxSafeLeafCount_Bounds. /review re-iteration flagged the prior
	// derivation as brittle to constant edits.
	// As of Week 11 Phase 3, this is defense-in-depth ABOVE the operational cap
	// params.AGNT2MaxStepsPerCall = 10_000. Numerically: 26_843_545 > 10_000.
	// The operational cap is the tighter (smaller) bound that fires first in
	// both Run and RequiredGas; this wrap protector is the unreachable upper
	// bound, kept so a future bump to AGNT2MaxStepsPerCall that lifts it past
	// 26_843_545 can't silently disable the uint32-fit invariant — the
	// ordering check in TestStepCountCaps_Bounds fires first.
	maxSafeLeafCount uint64 = 26_843_545
	maxWorkflowIDLen        = 1024
)

// parseWorkflowID reads an ABI-encoded string (workflow_id) starting at byte 5
// of the calldata. It returns the raw string bytes, the total size of the ABI
// header (offset word, length word, string bytes + padding), and any error byte.
func parseWorkflowID(input []byte) ([]byte, uint64, byte) {
	if len(input) < 5+64 {
		return nil, 0, revertWorkflowIDInvalid
	}

	// Read offset (must be 0x20 for single dynamic arg)
	for i := 5; i < 36; i++ {
		if input[i] != 0 {
			return nil, 0, revertWorkflowIDInvalid
		}
	}
	if input[36] != 0x20 {
		return nil, 0, revertWorkflowIDInvalid
	}

	// Read length (must be >0 and <= maxWorkflowIDLen)
	for i := 37; i < 65; i++ {
		if input[i] != 0 {
			return nil, 0, revertWorkflowIDInvalid
		}
	}
	length := binary.BigEndian.Uint32(input[65:69])
	if length == 0 || length > maxWorkflowIDLen {
		return nil, 0, revertWorkflowIDInvalid
	}

	paddedLen := uint64((length + 31) / 32 * 32)
	if uint64(len(input)) < 5+64+paddedLen {
		return nil, 0, revertWorkflowIDInvalid
	}

	// Validate zero padding
	for i := uint32(69) + length; i < uint32(69)+uint32(paddedLen); i++ {
		if input[i] != 0 {
			return nil, 0, revertWorkflowIDInvalid
		}
	}

	id := input[69 : uint32(69)+length]
	abiHeaderSize := 64 + paddedLen
	return id, abiHeaderSize, 0
}

type agnt2Interaction struct{}

// Name implements vm.PrecompiledContract for tracing/registry purposes.
// Uppercase short token matches upstream convention (ECREC, SHA256, BN254_ADD).
func (c *agnt2Interaction) Name() string { return "AGNT2_INTERACTION" }

// RequiredGas mirrors Run()'s validation cheaply. It charges only base gas
// when input is malformed, the version byte is wrong, stepCount would trip
// the overflow guard, the operational MAX_STEPS_PER_CALL cap, or the calldata length is inconsistent with stepCount.
// This closes the gas-grief vector where a caller submits valid version and
// valid stepCount but truncated body — the EVM previously billed
// stepCount * agnt2PerStepGas before Run() rejected with revertMalformedCalldata
// in microseconds. Cheap syntactic checks only. Binding (Phase 3) and chain (Phase 4) checks are NOT mirrored — those are O(stepCount*keccak) and would make gas estimation expensive. Calls that pass syntactic checks but fail binding/chain in Run pay full declared step gas.
func (c *agnt2Interaction) RequiredGas(input []byte) uint64 {
	if len(input) < 5 {
		return params.AGNT2BaseGas
	}
	if input[0] != 0x00 {
		return params.AGNT2BaseGas
	}
	stepCount := uint64(binary.BigEndian.Uint32(input[1:5]))
	if stepCount > params.AGNT2MaxStepsPerCall {
		return params.AGNT2BaseGas
	}
	if stepCount > maxSafeLeafCount {
		return params.AGNT2BaseGas
	}
	_, abiHeaderSize, errCode := parseWorkflowID(input)
	if errCode != 0 {
		return params.AGNT2BaseGas
	}

	expectedLen := uint64(5) + abiHeaderSize + stepCount*agnt2LeafSize
	if uint64(len(input)) != expectedLen {
		return params.AGNT2BaseGas
	}

	return params.AGNT2BaseGas + stepCount*params.AGNT2PerStepGas
}

// validateAndBuildMMR validates the per-leaf binding + chain invariants and
// builds the MMR for the call's leaves. Returns the MMR root, the per-leaf
// events collected during validation, and any revert byte (0 = ok). The
// caller is responsible for committing events to globalAgnt2EventStore only
// on full success — partial events from a reverted call MUST NOT be
// observable via LastEmittedEvents() (mirrors EVM log journal rollback).
// Used by Run and exposed to tests so they can assert the root matches
// canonical encoding vectors.
func validateAndBuildMMR(input []byte, stepCount uint64, abiHeaderSize uint64, workflowID []byte) ([32]byte, []LeafEvent, byte) {
	if stepCount == 0 {
		// empty MMR
		m := &agnt2MMR{}
		return m.getRoot(), nil, 0
	}
	expectedWfHash := crypto.Keccak256(workflowID)
	leavesStart := uint64(5) + abiHeaderSize
	var prevHash [32]byte
	mmr := &agnt2MMR{}
	events := make([]LeafEvent, 0, stepCount)
	for i := uint64(0); i < stepCount; i++ {
		leafStart := leavesStart + i*agnt2LeafSize
		leafBytes := input[leafStart : leafStart+agnt2LeafSize]
		if !bytes.Equal(leafBytes[0:32], expectedWfHash) {
			return [32]byte{}, nil, revertWorkflowBindingMismatch
		}
		if !bytes.Equal(leafBytes[128:160], prevHash[:]) {
			return [32]byte{}, nil, revertLeafChainBroken
		}
		var leafHash [32]byte
		copy(leafHash[:], crypto.Keccak256(leafBytes))
		mmr.append(leafHash)

		// Phase 7 — collect per-step event for commit-on-success.
		var workflowIDHash, stepIDHash, agentRoleHash, payout [32]byte
		copy(workflowIDHash[:], leafBytes[0:32])
		copy(stepIDHash[:], leafBytes[32:64])
		copy(agentRoleHash[:], leafBytes[64:96])
		copy(payout[:], leafBytes[96:128])
		events = append(events, LeafEvent{
			WorkflowIDHash: workflowIDHash,
			StepIndex:      uint32(i),
			StepIDHash:     stepIDHash,
			AgentRoleHash:  agentRoleHash,
			Payout:         payout,
			LeafHash:       leafHash,
		})

		prevHash = leafHash
	}
	return mmr.getRoot(), events, 0
}

func (c *agnt2Interaction) Run(input []byte) ([]byte, error) {
	if len(input) < 5 {
		return []byte{revertMalformedCalldata}, ErrExecutionReverted
	}

	if input[0] != 0x00 {
		return []byte{revertInvalidVersion}, ErrExecutionReverted
	}

	stepCount := uint64(binary.BigEndian.Uint32(input[1:5]))
	if stepCount > params.AGNT2MaxStepsPerCall {
		return []byte{revertStepOverflow}, ErrExecutionReverted
	}
	if stepCount > maxSafeLeafCount {
		return []byte{revertStepOverflow}, ErrExecutionReverted
	}

	workflowID, abiHeaderSize, errCode := parseWorkflowID(input)
	if errCode != 0 {
		return []byte{errCode}, ErrExecutionReverted
	}

	// uint64 math throughout. On 32-bit Go builds, int(stepCount)*160 silently
	// overflows when stepCount > int32-max / agnt2LeafSize ≈ 13_421_772, even
	// though maxSafeLeafCount allows up to 26_843_545. uint64 closes that gap.
	//
	// Strict equality (!=, not <): ADR 002 says "total length is inconsistent
	// with step_count" produces revertMalformedCalldata. Trailing bytes are
	// "inconsistent" too — they have no defined meaning in the Week 9 raw-leaf
	// format. Week 10 will widen this to allow workflow_id ABI prefix bytes,
	// at which point the equality switches to an exact computed length that
	// includes the parsed string size.
	expectedLen := uint64(5) + abiHeaderSize + stepCount*agnt2LeafSize
	if uint64(len(input)) != expectedLen {
		return []byte{revertMalformedCalldata}, ErrExecutionReverted
	}

	root, events, errCode := validateAndBuildMMR(input, stepCount, abiHeaderSize, workflowID)
	if errCode != 0 {
		return []byte{errCode}, ErrExecutionReverted
	}
	// Phase 6 — publish root via native hook for op-node consumption.
	globalAgnt2RootStore.put(root)
	// Phase 7 — commit collected events on success only (mirrors EVM log
	// journal: a reverted call's logs are dropped; prior call's logs persist).
	globalAgnt2EventStore.commit(events)

	return nil, nil
}
