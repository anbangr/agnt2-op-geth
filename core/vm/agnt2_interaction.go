package vm

import (
	"encoding/binary"
	"errors"

	"github.com/ethereum/go-ethereum/params"
)

// ErrAGNT2Reverted is the sentinel returned alongside a one-byte error code.
// Per ADR 002 the EVM must treat failures as transaction reverts with the byte
// as return data. When this scaffold is wired into the active op-geth precompile
// registry (Week 10), the dispatch layer maps ErrAGNT2Reverted to
// vm.ErrExecutionReverted so the byte payload becomes EVM return data.
// Returning any non-nil error here guarantees the call fails per standard
// go-ethereum precompile semantics instead of silently succeeding.
var ErrAGNT2Reverted = errors.New("AGNT2: reverted")

// Revert codes returned alongside ErrAGNT2Reverted. Order is locked by ADR 002
// and the on-chain decoder; renumbering is a breaking change.
const (
	revertInvalidVersion    byte = 0x01 // byte 0 is not 0x00
	revertMalformedCalldata byte = 0x02 // total length is inconsistent with step_count
	revertStepOverflow      byte = 0x03 // step_count * 160 exceeds the calldata size limit
	revertTrieWriteFailed   byte = 0x04 // MMR leaf write failed (Week 10 only)
	revertNotImplemented    byte = 0x05 // stepCount > 0 in Week 9 — MMR writer is Week 10 scope
	revertWorkflowIDInvalid byte = 0x06 // workflow_id parsing failed (offset, length, padding, range)
)

const (
	agnt2LeafSize   uint64 = 160
	// maxSafeLeafCount = floor((2^32 - 1) / 160) = 26_843_545.
	// Pinned as an explicit literal (not a derivation) so a future change to
	// agnt2LeafSize can't silently shift the bound and mask a regression in
	// TestMaxSafeLeafCount_Bounds. /review re-iteration flagged the prior
	// derivation as brittle to constant edits.
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

// RequiredGas mirrors Run()'s validation cheaply. It charges only base gas
// when input is malformed, the version byte is wrong, stepCount would trip
// the overflow guard, or the calldata length is inconsistent with stepCount.
// This closes the gas-grief vector where a caller submits valid version and
// valid stepCount but truncated body — the EVM previously billed
// stepCount * agnt2PerStepGas before Run() rejected with revertMalformedCalldata
// in microseconds. Now: if Run() returns a revert code, RequiredGas returns
// only base gas. Codex+Security multi-specialist confirmed during /review.
//
// Week 9 scope: stepCount > 0 always reverts with revertNotImplemented (MMR
// writer is Week 10). RequiredGas mirrors that — base only — until Week 10
// flips revertNotImplemented to actual leaf writes. /review re-iteration
// 2026-04-26 closed the silent-success trust boundary that ADR 002 §Dual-Write
// Abort forbids.
func (c *agnt2Interaction) RequiredGas(input []byte) uint64 {
	if len(input) < 5 {
		return params.AGNT2BaseGas
	}
	if input[0] != 0x00 {
		return params.AGNT2BaseGas
	}
	stepCount := uint64(binary.BigEndian.Uint32(input[1:5]))
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
	// Week 9: stepCount > 0 reverts in Run, so charge base only. Once Week 10
	// wires the writer, drop this branch and bill the full per-step amount.
	if stepCount > 0 {
		return params.AGNT2BaseGas
	}
	return params.AGNT2BaseGas + stepCount*params.AGNT2PerStepGas
}

func (c *agnt2Interaction) Run(input []byte) ([]byte, error) {
	if len(input) < 5 {
		return []byte{revertMalformedCalldata}, ErrAGNT2Reverted
	}

	if input[0] != 0x00 {
		return []byte{revertInvalidVersion}, ErrAGNT2Reverted
	}

	stepCount := uint64(binary.BigEndian.Uint32(input[1:5]))
	if stepCount > maxSafeLeafCount {
		return []byte{revertStepOverflow}, ErrAGNT2Reverted
	}

	workflowID, abiHeaderSize, errCode := parseWorkflowID(input)
	if errCode != 0 {
		return []byte{errCode}, ErrAGNT2Reverted
	}
	_ = workflowID // forward compatibility for Phase 3

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
		return []byte{revertMalformedCalldata}, ErrAGNT2Reverted
	}

	// Week 9 trust boundary: validation passed but the MMR writer is Week 10
	// scope. Returning (nil, nil) here would silently signal "committed" to any
	// caller — exactly what ADR 002 §Dual-Write Abort forbids ("every COMPOSE
	// step committed to EVM state has a corresponding MMR leaf"). The
	// compensating control "precompile is not registered until Week 10" is
	// itself a Week 10 deferral (item 7), so we cannot rely on it.
	//
	// Active enforcement: stepCount > 0 reverts with revertNotImplemented (0x05)
	// until Week 10 wires the writer and replaces this branch. stepCount == 0
	// still succeeds — a zero-step call is a well-defined no-op and is required
	// by the on-chain entry-point smoke test.
	//
	// /review re-iteration 2026-04-26 — Claude adversarial subagent + ADR 002
	// §Dual-Write Abort.
	if stepCount > 0 {
		return []byte{revertNotImplemented}, ErrAGNT2Reverted
	}

	// TODO Week 10 — replace the stepCount>0 revert above with full integration:
	//   1. Parse the ABI-encoded workflow_id starting at byte 5; let wfBytes
	//      be its decoded length. Recompute expectedLen = 5 + wfBytes +
	//      stepCount*agnt2LeafSize and re-validate.
	//   2. For each leaf, verify leaf.workflowIdHash == keccak256(workflow_id)
	//      so a caller cannot pack leaves for workflow A under calldata
	//      claiming workflow B.
	//   3. Verify the prevLeafHash chain: leaf[i].prevLeafHash ==
	//      leafHash(leaf[i-1]), zero for i==0. A broken chain means the
	//      Week 10 commit would derive a root the verifier cannot match.
	//   4. Shadow-copy the MMR trie, append all leaves in topological order,
	//      commit only after every leaf write succeeds.
	//   5. Update the L2 block header interaction root.
	//   6. On any failure: return []byte{0x04}, ErrAGNT2Reverted.
	// Forward-compatibility: Week 9 accepts calldata where bytes
	// 5..(5+stepCount*160) are raw leaves with no preceding workflow_id ABI
	// string. Week 10 will reject those — agnt2_interaction_test.go locks the
	// Week 9 acceptance set so the divergence is documented, not silent.

	return nil, nil
}
