package vm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// makeInputWithWfID builds calldata: version + stepCount(BE uint32) + workflowID ABI string + body bytes.
func makeInputWithWfID(version byte, wfID string, stepCount uint32, bodyBytes int) []byte {
	idBytes := []byte(wfID)
	l := len(idBytes)
	paddedLen := (l + 31) / 32 * 32

	buf := make([]byte, 5+64+paddedLen+bodyBytes)
	buf[0] = version
	binary.BigEndian.PutUint32(buf[1:5], stepCount)

	// offset (0x20)
	buf[36] = 0x20

	// length
	binary.BigEndian.PutUint32(buf[65:69], uint32(l))

	// string bytes
	copy(buf[69:69+l], idBytes)

	// body
	if bodyBytes > 0 {
		// 0xAB pattern is recognizable in test failures and not all-zero.
		for i := 5 + 64 + paddedLen; i < len(buf); i++ {
			buf[i] = 0xAB
		}
	}
	return buf
}

// makeInput defaults to a valid workflowID so existing tests continue to test what they meant to.
func makeInput(version byte, stepCount uint32, bodyBytes int) []byte {
	return makeInputWithWfID(version, "test-wf", stepCount, bodyBytes)
}

// makeLeaf builds a 160-byte leaf with the given workflowIdHash in the
// first 32 bytes; the remaining 128 bytes are filled with `fillByte`.
func makeLeaf(wfHash []byte, fillByte byte) []byte {
	leaf := make([]byte, 160)
	copy(leaf[0:32], wfHash)
	for i := 32; i < 160; i++ {
		leaf[i] = fillByte
	}
	return leaf
}

// makeInputWithLeaves builds version + stepCount(BE) + ABI(workflow_id) + leaves.
// wfID is the workflow_id string. leaves is a slice of 160-byte leaves; len(leaves)
// must be a multiple of 160. The caller is responsible for the leaves' workflowIdHash
// matching keccak256(wfID) if they want the binding check to pass.
func makeInputWithLeaves(wfID string, leaves []byte) []byte {
	wfBytes := []byte(wfID)
	length := uint64(len(wfBytes))
	paddedLen := (length + 31) / 32 * 32
	stepCount := uint32(len(leaves) / 160)

	buf := make([]byte, 5+64+paddedLen+uint64(len(leaves)))
	buf[0] = 0x00 // version
	binary.BigEndian.PutUint32(buf[1:5], stepCount)
	buf[36] = 0x20                                 // offset
	binary.BigEndian.PutUint64(buf[61:69], length) // length in low bytes (uint256 BE; high bytes implicit zero)
	copy(buf[69:69+length], wfBytes)
	// padding bytes [69+length..69+paddedLen) already zero from make()
	copy(buf[5+64+paddedLen:], leaves)
	return buf
}

// makeChainedLeaves builds n leaves where each leaf[i].prevLeafHash =
// keccak256(leaf[i-1]) and leaf[0].prevLeafHash = bytes32(0). All leaves
// share the given wfHash. Other fields use deterministic patterns derived
// from i (so different stepIdHashes yield distinct leafHashes).
func makeChainedLeaves(wfHash []byte, n int) []byte {
	result := make([]byte, n*160)
	var prevHash [32]byte
	for i := 0; i < n; i++ {
		leaf := result[i*160 : (i+1)*160]
		copy(leaf[0:32], wfHash)
		// stepIdHash: vary by i so leafHashes differ
		leaf[63] = byte(i + 1)
		// agentRoleHash: vary by i
		leaf[95] = byte(i + 1)
		// payout: i+1 in low byte
		leaf[127] = byte(i + 1)
		// prevLeafHash: previous leafHash
		copy(leaf[128:160], prevHash[:])
		// Compute next prevHash
		copy(prevHash[:], crypto.Keccak256(leaf))
	}
	return result
}

func TestParseWorkflowID_Valid(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 1)
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if !errors.Is(err, ErrAGNT2Reverted) {
		t.Fatalf("expected ErrAGNT2Reverted, got %v", err)
	}
	if len(out) != 1 || out[0] != revertNotImplemented {
		t.Fatalf("expected 0x05, got %v", out)
	}
}

func TestParseWorkflowID_EmptyRejected(t *testing.T) {
	c := &agnt2Interaction{}
	out, err := c.Run(makeInputWithWfID(0x00, "", 1, int(agnt2LeafSize)))
	if !errors.Is(err, ErrAGNT2Reverted) {
		t.Fatalf("expected ErrAGNT2Reverted, got %v", err)
	}
	if len(out) != 1 || out[0] != revertWorkflowIDInvalid {
		t.Fatalf("expected 0x06, got %v", out)
	}
}

func TestParseWorkflowID_BadOffset(t *testing.T) {
	c := &agnt2Interaction{}
	input := makeInputWithWfID(0x00, "test", 1, int(agnt2LeafSize))
	input[36] = 0x40 // Corrupt offset
	out, err := c.Run(input)
	if !errors.Is(err, ErrAGNT2Reverted) || out[0] != revertWorkflowIDInvalid {
		t.Fatalf("expected 0x06, got %v", out)
	}
}

func TestParseWorkflowID_LengthTooBig(t *testing.T) {
	c := &agnt2Interaction{}
	input := makeInputWithWfID(0x00, "test", 1, int(agnt2LeafSize))
	binary.BigEndian.PutUint32(input[65:69], maxWorkflowIDLen+1) // Corrupt length
	out, err := c.Run(input)
	if !errors.Is(err, ErrAGNT2Reverted) || out[0] != revertWorkflowIDInvalid {
		t.Fatalf("expected 0x06, got %v", out)
	}
}

func TestParseWorkflowID_NonZeroPadding(t *testing.T) {
	c := &agnt2Interaction{}
	input := makeInputWithWfID(0x00, "test", 1, int(agnt2LeafSize))
	input[69+4] = 0xFF // Corrupt padding
	out, err := c.Run(input)
	if !errors.Is(err, ErrAGNT2Reverted) || out[0] != revertWorkflowIDInvalid {
		t.Fatalf("expected 0x06, got %v", out)
	}
}

func TestParseWorkflowID_TrailingBytes(t *testing.T) {
	c := &agnt2Interaction{}
	input := makeInputWithWfID(0x00, "test", 1, int(agnt2LeafSize))
	input = append(input, 0x00) // extra byte
	out, err := c.Run(input)
	if !errors.Is(err, ErrAGNT2Reverted) || out[0] != revertMalformedCalldata {
		t.Fatalf("expected 0x02, got %v", out)
	}
}

func TestParseWorkflowID_ZeroSteps(t *testing.T) {
	c := &agnt2Interaction{}
	out, err := c.Run(makeInputWithWfID(0x00, "hello", 0, 0))
	if err != nil || out != nil {
		t.Fatalf("zero steps should succeed, got %v, %v", out, err)
	}
}

func TestParseWorkflowID_LengthOne(t *testing.T) {
	c := &agnt2Interaction{}
	out, err := c.Run(makeInputWithWfID(0x00, "x", 0, 0))
	if err != nil || out != nil {
		t.Fatalf("length 1 should succeed, got %v, %v", out, err)
	}
}

func TestParseWorkflowID_LengthMaxAccepted(t *testing.T) {
	c := &agnt2Interaction{}
	wf := string(bytes.Repeat([]byte{'a'}, 1024))
	out, err := c.Run(makeInputWithWfID(0x00, wf, 0, 0))
	if err != nil || out != nil {
		t.Fatalf("length 1024 should succeed, got %v, %v", out, err)
	}
}

func TestParseWorkflowID_LengthOverMax(t *testing.T) {
	c := &agnt2Interaction{}
	wf := string(bytes.Repeat([]byte{'a'}, 1025))
	out, err := c.Run(makeInputWithWfID(0x00, wf, 0, 0))
	if !errors.Is(err, ErrAGNT2Reverted) || len(out) == 0 || out[0] != revertWorkflowIDInvalid {
		t.Fatalf("expected 0x06, got %v", out)
	}
}

func TestParseWorkflowID_TooShortForHeader(t *testing.T) {
	c := &agnt2Interaction{}
	input := make([]byte, 69)
	input[0] = 0x00 // version
	// length field implicitly 0 (all zeroes)
	out, err := c.Run(input)
	if !errors.Is(err, ErrAGNT2Reverted) || len(out) == 0 || out[0] != revertWorkflowIDInvalid {
		t.Fatalf("expected 0x06, got %v", out)
	}
}

func TestRequiredGas_InvalidWorkflowID_BaseOnly(t *testing.T) {
	c := &agnt2Interaction{}

	stepCount := uint32(100)

	// 1. bad-offset
	badOffset := makeInputWithWfID(0x00, "test", stepCount, int(stepCount)*int(agnt2LeafSize))
	badOffset[36] = 0x40

	// 2. empty workflow_id
	emptyWf := makeInputWithWfID(0x00, "", stepCount, int(stepCount)*int(agnt2LeafSize))

	// 3. oversized workflow_id
	oversizedWf := makeInputWithWfID(0x00, string(bytes.Repeat([]byte{'a'}, 1025)), stepCount, int(stepCount)*int(agnt2LeafSize))

	rejecting := [][]byte{badOffset, emptyWf, oversizedWf}

	for _, in := range rejecting {
		gas := c.RequiredGas(in)
		if gas != params.AGNT2BaseGas {
			t.Fatalf("RequiredGas charged %d (> base %d) for parseWorkflowID rejection", gas, params.AGNT2BaseGas)
		}
	}
}

func TestRun_SuccessZeroSteps(t *testing.T) {
	c := &agnt2Interaction{}
	out, err := c.Run(makeInput(0x00, 0, 0))
	if err != nil {
		t.Fatalf("zero-step call should succeed; got err=%v out=%v", err, out)
	}
	if out != nil {
		t.Fatalf("zero-step call should return nil output; got %v", out)
	}
}

// Week 9: stepCount > 0 is intentionally NOT implemented — Run reverts with
// revertNotImplemented (0x05) until Week 10 wires the MMR writer. This closes
// the silent-success trust boundary that ADR 002 §Dual-Write Abort forbids.
// /review re-iteration 2026-04-26 — Claude adversarial subagent finding.
func TestRun_NotImplementedOneStep(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 1)
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if !errors.Is(err, ErrAGNT2Reverted) {
		t.Fatalf("Week 9: one-step call must revert with ErrAGNT2Reverted; got err=%v", err)
	}
	if len(out) != 1 || out[0] != revertNotImplemented {
		t.Fatalf("expected revertNotImplemented (0x%02x); got %v", revertNotImplemented, out)
	}
}

// Sweep stepCount=1..1000 to confirm Week 9 reverts every well-formed
// stepCount > 0 case with revertNotImplemented. Once Week 10 wires the writer,
// flip this test to TestRun_AcceptsAnyValidStepCount.
func TestRun_NotImplementedSweep(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-sweep"
	expectedHash := crypto.Keccak256([]byte(wfID))
	for _, stepCount := range []uint32{1, 2, 10, 100, 1000} {
		leaves := makeChainedLeaves(expectedHash, int(stepCount))
		input := makeInputWithLeaves(wfID, leaves)
		out, err := c.Run(input)
		if !errors.Is(err, ErrAGNT2Reverted) {
			t.Fatalf("stepCount=%d: expected ErrAGNT2Reverted, got err=%v", stepCount, err)
		}
		if len(out) != 1 || out[0] != revertNotImplemented {
			t.Fatalf("stepCount=%d: expected revertNotImplemented (0x%02x), got %v",
				stepCount, revertNotImplemented, out)
		}
	}
}

func TestRun_WorkflowBindingValid_OneStep(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 1)
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if !errors.Is(err, ErrAGNT2Reverted) {
		t.Fatalf("expected ErrAGNT2Reverted, got %v", err)
	}
	if len(out) != 1 || out[0] != revertNotImplemented {
		t.Fatalf("expected revertNotImplemented (0x05), got %v", out)
	}
}

func TestRun_WorkflowBindingValid_ThreeStep(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 3)
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if !errors.Is(err, ErrAGNT2Reverted) {
		t.Fatalf("expected ErrAGNT2Reverted, got %v", err)
	}
	if len(out) != 1 || out[0] != revertNotImplemented {
		t.Fatalf("expected revertNotImplemented (0x05), got %v", out)
	}
}

func TestRun_ChainValid_OneStep(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 1)
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if !errors.Is(err, ErrAGNT2Reverted) {
		t.Fatalf("expected ErrAGNT2Reverted, got %v", err)
	}
	if len(out) != 1 || out[0] != revertNotImplemented {
		t.Fatalf("expected revertNotImplemented (0x05), got %v", out)
	}
}

func TestRun_ChainValid_ThreeStep(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 3)
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if !errors.Is(err, ErrAGNT2Reverted) {
		t.Fatalf("expected ErrAGNT2Reverted, got %v", err)
	}
	if len(out) != 1 || out[0] != revertNotImplemented {
		t.Fatalf("expected revertNotImplemented (0x05), got %v", out)
	}
}

func TestRun_ChainBrokenAtFirst(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 1)
	leaves[160-1] = 0xFF // corrupt prevLeafHash of leaf[0]
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if !errors.Is(err, ErrAGNT2Reverted) {
		t.Fatalf("expected ErrAGNT2Reverted, got %v", err)
	}
	if len(out) != 1 || out[0] != revertLeafChainBroken {
		t.Fatalf("expected revertLeafChainBroken (0x08), got %v", out)
	}
}

func TestRun_ChainBrokenAtMiddle(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 3)
	leaves[160+160-1] = 0xFF // corrupt prevLeafHash of leaf[1]
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if !errors.Is(err, ErrAGNT2Reverted) {
		t.Fatalf("expected ErrAGNT2Reverted, got %v", err)
	}
	if len(out) != 1 || out[0] != revertLeafChainBroken {
		t.Fatalf("expected revertLeafChainBroken (0x08), got %v", out)
	}
}

func TestRun_ChainBrokenAtLast(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 3)
	leaves[2*160+160-1] = 0xFF // corrupt prevLeafHash of leaf[2]
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if !errors.Is(err, ErrAGNT2Reverted) {
		t.Fatalf("expected ErrAGNT2Reverted, got %v", err)
	}
	if len(out) != 1 || out[0] != revertLeafChainBroken {
		t.Fatalf("expected revertLeafChainBroken (0x08), got %v", out)
	}
}

func TestRun_BindingPrecedesChain(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 1)
	leaves[0] ^= 0xFF    // corrupt workflowIdHash -> binding mismatch
	leaves[160-1] = 0xFF // corrupt prevLeafHash -> chain broken
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if !errors.Is(err, ErrAGNT2Reverted) {
		t.Fatalf("expected ErrAGNT2Reverted, got %v", err)
	}
	if len(out) != 1 || out[0] != revertWorkflowBindingMismatch {
		t.Fatalf("expected revertWorkflowBindingMismatch (0x07), got %v", out)
	}
}

func TestRun_WorkflowBindingMismatch_FirstLeaf(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	wrongHash := crypto.Keccak256([]byte("test-wf-002"))
	leaves := makeChainedLeaves(expectedHash, 1)
	copy(leaves[0:32], wrongHash)
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if !errors.Is(err, ErrAGNT2Reverted) {
		t.Fatalf("expected ErrAGNT2Reverted, got %v", err)
	}
	if len(out) != 1 || out[0] != revertWorkflowBindingMismatch {
		t.Fatalf("expected revertWorkflowBindingMismatch (0x07), got %v", out)
	}
}

func TestRun_WorkflowBindingMismatch_LastLeaf(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	wrongHash := crypto.Keccak256([]byte("test-wf-002"))
	leaves := makeChainedLeaves(expectedHash, 3)
	copy(leaves[2*160:2*160+32], wrongHash)
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if !errors.Is(err, ErrAGNT2Reverted) {
		t.Fatalf("expected ErrAGNT2Reverted, got %v", err)
	}
	if len(out) != 1 || out[0] != revertWorkflowBindingMismatch {
		t.Fatalf("expected revertWorkflowBindingMismatch (0x07), got %v", out)
	}
}

func TestRun_WorkflowBindingMismatch_MiddleLeaf(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	wrongHash := crypto.Keccak256([]byte("test-wf-002"))
	leaves := makeChainedLeaves(expectedHash, 3)
	copy(leaves[160:160+32], wrongHash)
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if !errors.Is(err, ErrAGNT2Reverted) {
		t.Fatalf("expected ErrAGNT2Reverted, got %v", err)
	}
	if len(out) != 1 || out[0] != revertWorkflowBindingMismatch {
		t.Fatalf("expected revertWorkflowBindingMismatch (0x07), got %v", out)
	}
}

func TestRequiredGas_WorkflowBindingMismatch_BaseOnly(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	wrongHash := crypto.Keccak256([]byte("test-wf-002"))
	leaves := make([]byte, 0, 100*160)
	for i := 0; i < 100; i++ {
		leaves = append(leaves, makeLeaf(wrongHash, 0xAA)...)
	}
	input := makeInputWithLeaves(wfID, leaves)

	// Phase 5 gas check: we expect only base gas, not step gas.
	gas := c.RequiredGas(input)
	if gas != params.AGNT2BaseGas {
		t.Fatalf("RequiredGas charged %d (> base %d) for binding mismatch", gas, params.AGNT2BaseGas)
	}
}

func TestRun_RevertCodes(t *testing.T) {
	c := &agnt2Interaction{}
	cases := []struct {
		name     string
		input    []byte
		wantCode byte
	}{
		{"empty input", []byte{}, revertMalformedCalldata},
		{"3 bytes", []byte{0x00, 0x00, 0x00}, revertMalformedCalldata},
		{"4 bytes", []byte{0x00, 0x00, 0x00, 0x00}, revertMalformedCalldata},
		{"bad version", makeInput(0x01, 0, 0), revertInvalidVersion},
		{"bad version high", makeInput(0xFF, 0, 0), revertInvalidVersion},
		{"declared 1 step but no leaf bytes", makeInput(0x00, 1, 0), revertMalformedCalldata},
		{"declared 1 step, 159 leaf bytes (one short)", makeInput(0x00, 1, 159), revertMalformedCalldata},
		{"declared 2 steps, 319 leaf bytes (one short)", makeInput(0x00, 2, 319), revertMalformedCalldata},
		// Trailing-bytes rejection (ADR 002: "total length is inconsistent with step_count")
		{"declared 0 steps but 1 trailing byte", makeInput(0x00, 0, 1), revertMalformedCalldata},
		{"declared 1 step, 161 leaf bytes (one extra)", makeInput(0x00, 1, 161), revertMalformedCalldata},
		{"declared 2 steps, 321 leaf bytes (one extra)", makeInput(0x00, 2, 321), revertMalformedCalldata},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := c.Run(tc.input)
			if !errors.Is(err, ErrAGNT2Reverted) {
				t.Fatalf("expected ErrAGNT2Reverted; got %v", err)
			}
			if len(out) != 1 || out[0] != tc.wantCode {
				t.Fatalf("expected revert code 0x%02x; got %v", tc.wantCode, out)
			}
		})
	}
}

func TestRun_StepOverflow(t *testing.T) {
	c := &agnt2Interaction{}
	overflow := uint32(maxSafeLeafCount + 1)
	input := makeInput(0x00, overflow, 0)
	out, err := c.Run(input)
	if !errors.Is(err, ErrAGNT2Reverted) {
		t.Fatalf("expected ErrAGNT2Reverted; got %v", err)
	}
	if len(out) != 1 || out[0] != revertStepOverflow {
		t.Fatalf("expected revertStepOverflow; got 0x%02x", out[0])
	}
}

func TestRun_BoundaryAtMaxSafeLeafCount(t *testing.T) {
	c := &agnt2Interaction{}
	// stepCount = maxSafeLeafCount must NOT trigger STEP_OVERFLOW. Sending only
	// the header surfaces MALFORMED instead. Confirms `> max` not `>= max`.
	atMax := uint32(maxSafeLeafCount)
	input := makeInput(0x00, atMax, 0)
	out, err := c.Run(input)
	if !errors.Is(err, ErrAGNT2Reverted) {
		t.Fatalf("expected ErrAGNT2Reverted; got %v", err)
	}
	if len(out) != 1 || out[0] != revertMalformedCalldata {
		t.Fatalf("at maxSafeLeafCount, expected revertMalformedCalldata; got 0x%02x", out[0])
	}
}

func TestRequiredGas(t *testing.T) {
	c := &agnt2Interaction{}
	cases := []struct {
		name  string
		input []byte
		want  uint64
	}{
		{"empty input -> base only", []byte{}, params.AGNT2BaseGas},
		{"4 bytes -> base only", []byte{0x00, 0x00, 0x00, 0x00}, params.AGNT2BaseGas},
		{"bad version -> base only (no step gas)", makeInput(0x01, 1000, 0), params.AGNT2BaseGas},
		{"valid 0 steps", makeInput(0x00, 0, 0), params.AGNT2BaseGas},
		// Week 9: stepCount > 0 reverts with revertNotImplemented in Run, so
		// RequiredGas charges base only. Once Week 10 wires the writer, these
		// cases flip back to base + N*perStep.
		{"valid 1 step (Week 9 revert)", makeInput(0x00, 1, 160), params.AGNT2BaseGas},
		{"valid 100 steps (Week 9 revert)", makeInput(0x00, 100, 16000), params.AGNT2BaseGas},
		{"overflow stepCount -> base only", makeInput(0x00, uint32(maxSafeLeafCount+1), 0), params.AGNT2BaseGas},
		// Length-grief regression — multi-specialist confirmed during /review.
		// Caller declares stepCount=1000 but supplies only the header.
		// Pre-fix: billed 21000 + 1000*2000 = 2_021_000 gas while Run() rejects
		// in microseconds. Post-fix: base gas only.
		{"length-grief: stepCount=1000, short body", makeInput(0x00, 1000, 0), params.AGNT2BaseGas},
		{"length-grief: stepCount=1, 159-byte body (short)", makeInput(0x00, 1, 159), params.AGNT2BaseGas},
		{"length-grief: stepCount=1, 161-byte body (long)", makeInput(0x00, 1, 161), params.AGNT2BaseGas},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := c.RequiredGas(tc.input)
			if got != tc.want {
				t.Fatalf("RequiredGas: want %d, got %d", tc.want, got)
			}
		})
	}
}

// TestRequiredGas_Run_NoOvercharge: Run rejects ⇒ RequiredGas <= base gas.
// Week 9: this includes well-formed stepCount > 0 calls, since Run reverts
// with revertNotImplemented for those.
func TestRequiredGas_Run_NoOvercharge(t *testing.T) {
	c := &agnt2Interaction{}
	rejecting := [][]byte{
		{},
		{0x00, 0x00, 0x00, 0x00},      // < 5 bytes
		makeInput(0x01, 1000, 160000), // bad version
		makeInput(0x00, uint32(maxSafeLeafCount+1), 0), // overflow
		makeInput(0x00, 1000, 0),                       // length-grief: declared 1000 steps, no body
		makeInput(0x00, 1, 159),                        // length-grief: short body
		makeInput(0x00, 1, 161),                        // length-grief: long body (trailing)
		// Week 9 trust boundary — well-formed stepCount > 0 reverts with
		// revertNotImplemented (will flip back to "accepted" in Week 10).
		makeInput(0x00, 1, 160),
		makeInput(0x00, 100, 16000),
	}
	for _, in := range rejecting {
		gas := c.RequiredGas(in)
		if gas > params.AGNT2BaseGas {
			t.Fatalf("RequiredGas charged %d (> base) for input Run rejects: %v", gas, in[:min(len(in), 16)])
		}
		if _, err := c.Run(in); err == nil {
			t.Fatalf("expected Run to reject; it succeeded for input %v", in[:min(len(in), 16)])
		}
	}
}

// TestRequiredGas_Run_AcceptanceInvariant: when Run accepts, RequiredGas charges
// exactly base + stepCount*perStep. The other side of the gas-correctness
// contract — testing specialist requested this during /review.
//
// Week 9: only stepCount == 0 is "accepted" (returns success). All stepCount > 0
// cases revert (see TestRun_NotImplementedSweep). Week 10 will widen this set
// once the MMR writer is wired — at which point this test loops over all valid
// stepCounts.
func TestRequiredGas_Run_AcceptanceInvariant(t *testing.T) {
	c := &agnt2Interaction{}
	for _, stepCount := range []uint32{0} {
		input := makeInput(0x00, stepCount, int(stepCount)*int(agnt2LeafSize))
		out, err := c.Run(input)
		if err != nil || out != nil {
			t.Fatalf("Run rejected stepCount=%d: out=%v err=%v", stepCount, out, err)
		}
		want := params.AGNT2BaseGas + uint64(stepCount)*params.AGNT2PerStepGas
		got := c.RequiredGas(input)
		if got != want {
			t.Fatalf("stepCount=%d: RequiredGas want %d, got %d", stepCount, want, got)
		}
	}
}

// TestRevertCodeValues pins the byte values of the named constants. ADR 002
// and the on-chain decoder depend on these exact values; renumbering is a
// breaking change and must be a deliberate, reviewed event.
func TestRevertCodeValues(t *testing.T) {
	if revertInvalidVersion != 0x01 {
		t.Errorf("revertInvalidVersion = 0x%02x, want 0x01", revertInvalidVersion)
	}
	if revertMalformedCalldata != 0x02 {
		t.Errorf("revertMalformedCalldata = 0x%02x, want 0x02", revertMalformedCalldata)
	}
	if revertStepOverflow != 0x03 {
		t.Errorf("revertStepOverflow = 0x%02x, want 0x03", revertStepOverflow)
	}
	if revertTrieWriteFailed != 0x04 {
		t.Errorf("revertTrieWriteFailed = 0x%02x, want 0x04", revertTrieWriteFailed)
	}
	if revertNotImplemented != 0x05 {
		t.Errorf("revertNotImplemented = 0x%02x, want 0x05", revertNotImplemented)
	}
	if revertWorkflowIDInvalid != 0x06 {
		t.Errorf("revertWorkflowIDInvalid = 0x%02x, want 0x06", revertWorkflowIDInvalid)
	}
	if revertWorkflowBindingMismatch != 0x07 {
		t.Errorf("revertWorkflowBindingMismatch = 0x%02x, want 0x07", revertWorkflowBindingMismatch)
	}
	if revertLeafChainBroken != 0x08 {
		t.Errorf("revertLeafChainBroken = 0x%02x, want 0x08", revertLeafChainBroken)
	}
}

// Boundary sanity: maxSafeLeafCount * agnt2LeafSize must fit in uint32
// without wrap, and (maxSafeLeafCount + 1) * agnt2LeafSize must wrap.
// Also pins the literal value (26_843_545) so a future edit to agnt2LeafSize
// can't silently shift the bound. /review re-iteration 2026-04-26.
func TestMaxSafeLeafCount_Bounds(t *testing.T) {
	if maxSafeLeafCount != 26_843_545 {
		t.Fatalf("maxSafeLeafCount changed: want 26_843_545, got %d", maxSafeLeafCount)
	}
	if maxSafeLeafCount*agnt2LeafSize > uint64(^uint32(0)) {
		t.Fatalf("maxSafeLeafCount*leafSize must fit in uint32; got %d", maxSafeLeafCount*agnt2LeafSize)
	}
	if (maxSafeLeafCount+1)*agnt2LeafSize <= uint64(^uint32(0)) {
		t.Fatalf("(maxSafeLeafCount+1)*leafSize must exceed uint32; got %d", (maxSafeLeafCount+1)*agnt2LeafSize)
	}
}
