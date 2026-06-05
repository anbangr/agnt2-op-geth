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
	revertStepOverflow            byte = 0x03 // step_count > params.AGNT2MaxStepsPerCall (operational cap) OR step_count * 160 exceeds uint32 (wrap protector)
	revertTrieWriteFailed         byte = 0x04 // MMR leaf write failed (Week 10 only)
	revertNotImplemented          byte = 0x05 // unused — retired by Phase 5
	revertWorkflowIDInvalid       byte = 0x06 // workflow_id parsing failed (offset, length, padding, range)
	revertWorkflowBindingMismatch byte = 0x07 // leaf.workflowIdHash != keccak256(workflow_id)
	revertLeafChainBroken         byte = 0x08 // leaf[i].prevLeafHash != leafHash(leaf[i-1])
	// revertStaticCall is returned when the precompile is invoked under
	// STATICCALL semantics (read-only). The precompile MUST emit per-leaf
	// LOGs for op-node MMR folding (Week 11 Phase 6); a silent "success but
	// no log" outcome under STATICCALL would break consensus because the
	// post-hook skips log emission while Run still publishes the root —
	// callers and verifiers would observe divergent state for the same
	// calldata depending only on the call mode. Rejecting at the post-hook
	// is the consensus-safe contract: STATICCALL into 0x0BC2 always reverts.
	revertStaticCall byte = 0x09
)

const (
	agnt2LeafSize uint64 = 160
	// maxSafeLeafCount = floor((2^32 - 1) / 160) = 26_843_545.
	// Pinned as an explicit literal (not a derivation) so a future change to
	// agnt2LeafSize can't silently shift the bound and mask a regression in
	// TestMaxSafeLeafCount_Bounds. /review re-iteration flagged the prior
	// derivation as brittle to constant edits.
	// As of Week 11 Phase 6, this is defense-in-depth ABOVE the operational cap
	// params.AGNT2MaxStepsPerCall = 4_500. Numerically: 26_843_545 > 4_500.
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
//
// Week 11 Phase 6: AGNT2PerStepGas now bundles the post-success LOG cost
// (375 base + 2*375 topics + 160*8 data bytes = 2_405 gas per leaf) charged
// up-front so the dispatcher need not re-bill at AddLog time. Calls that
// fail (or are STATICCALL-rejected) revert via ErrExecutionReverted, which
// the EVM treats as gas-refund-on-revert — caller's remaining gas is preserved.
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

// agnt2ParseLeaves runs the full Run() validation pipeline (version, length,
// workflow_id ABI parse, per-leaf binding + chain check, MMR build) and
// returns (root, events, errCode). errCode == 0 indicates success.
//
// Phase 6 introduced this as the SHARED parser between Run() and the
// post-success dispatcher (evmAGNT2PostHook). Both must observe identical
// validation outcomes — if they ever diverge, a STATICCALL or non-success
// path could silently emit logs that don't correspond to a successful root
// publication, breaking the consensus invariant that "logs exist iff the
// root was committed". Routing both through this single function makes
// re-parsing the dispatcher does cheap and consistent.
//
// On success, root + len(events) == stepCount; on failure (errCode != 0),
// returns zero root and nil events (matches the pre-Phase-6 contract that
// partial events from a reverted call are NOT observable).
func agnt2ParseLeaves(input []byte) (root [32]byte, events []LeafEvent, errCode byte) {
	if len(input) < 5 {
		return [32]byte{}, nil, revertMalformedCalldata
	}
	if input[0] != 0x00 {
		return [32]byte{}, nil, revertInvalidVersion
	}
	stepCount := uint64(binary.BigEndian.Uint32(input[1:5]))
	if stepCount > params.AGNT2MaxStepsPerCall {
		return [32]byte{}, nil, revertStepOverflow
	}
	if stepCount > maxSafeLeafCount {
		return [32]byte{}, nil, revertStepOverflow
	}
	workflowID, abiHeaderSize, errCode := parseWorkflowID(input)
	if errCode != 0 {
		return [32]byte{}, nil, errCode
	}
	// uint64 math throughout. On 32-bit Go builds, int(stepCount)*160 silently
	// overflows when stepCount > int32-max / agnt2LeafSize ≈ 13_421_772, even
	// though maxSafeLeafCount allows up to 26_843_545. uint64 closes that gap.
	expectedLen := uint64(5) + abiHeaderSize + stepCount*agnt2LeafSize
	if uint64(len(input)) != expectedLen {
		return [32]byte{}, nil, revertMalformedCalldata
	}
	return validateAndBuildMMR(input, stepCount, abiHeaderSize, workflowID)
}

// validateAndBuildMMR validates the per-leaf binding + chain invariants and
// builds the MMR for the call's leaves. Returns the MMR root, the per-leaf
// events collected during validation, and any revert byte (0 = ok). Used by
// agnt2ParseLeaves and the canonical-encoding test vectors so they can
// assert the root matches Go-side encoding vectors directly.
func validateAndBuildMMR(input []byte, stepCount uint64, abiHeaderSize uint64, workflowID []byte) ([32]byte, []LeafEvent, byte) {
	if stepCount == 0 {
		// empty MMR. Route through the trie wrapper so the empty-root path is
		// the same code the benchmark exercises; trie.Root() over zero leaves
		// is byte-identical to agnt2MMR.getRoot() (keccak256("")).
		return newAgnt2Trie().Root(), nil, 0
	}
	expectedWfHash := crypto.Keccak256(workflowID)
	leavesStart := uint64(5) + abiHeaderSize
	var prevHash [32]byte
	// WS3: route the per-leaf append through the interaction-trie wrapper. The
	// wrapper embeds the same agnt2MMR and appends in identical order, so
	// trie.Root() is BYTE-IDENTICAL to a bare agnt2MMR.getRoot() over this leaf
	// sequence — the on-chain root and FoldInteractionRoot output are
	// unchanged (regression-locked by TestAgnt2Trie_RootParity / T5). The
	// typed interactionKey is recorded alongside (via the O(1) Append hot path,
	// NOT the proof-building AppendTyped) so the production root path is the
	// same code the inclusion/update-proof benchmark measures, with no per-leaf
	// proof cost on the consensus path.
	trie := newAgnt2Trie()
	var wfHash32 [32]byte
	copy(wfHash32[:], expectedWfHash)
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
		// Append to the embedded MMR (root source) and record the typed
		// interactionKey for this (workflow, step) invocation.
		trie.Append(interactionKey(wfHash32, uint32(i)), leafHash)

		// Phase 6 — collect per-step event for post-success log emission via
		// the EVM dispatcher (evmAGNT2PostHook). Run() itself does NOT
		// commit to any global store; the dispatcher re-parses calldata to
		// emit logs only on the success path so journal-revert semantics
		// match the EVM Log model.
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
	return trie.Root(), events, 0
}

func (c *agnt2Interaction) Run(input []byte) ([]byte, error) {
	_, _, errCode := agnt2ParseLeaves(input)
	if errCode != 0 {
		return []byte{errCode}, ErrExecutionReverted
	}
	// Phase 7 — Run() no longer publishes a root anywhere. The canonical
	// MMR root is derived in core/types.FoldInteractionRoot from the per-leaf
	// logs that evmAGNT2PostHook emits on the success path, and committed
	// in the block header by the sequencer (consensus/beacon FinalizeAndAssemble).
	// Block import re-folds the receipts and rejects mismatches.
	return nil, nil
}
