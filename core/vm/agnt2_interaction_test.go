package vm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"sync"
	"testing"
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

// TestParseWorkflowID_Valid was asserting 0x05 because Week 9 rejected valid input.
// Now that Phase 5 is active, valid input succeeds. We simply rename to
// demonstrate parsing doesn't crash.
func TestParseWorkflowID_Valid(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 1)
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if err != nil || out != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestParseWorkflowID_EmptyRejected(t *testing.T) {
	c := &agnt2Interaction{}
	out, err := c.Run(makeInputWithWfID(0x00, "", 1, int(agnt2LeafSize)))
	if !errors.Is(err, ErrExecutionReverted) {
		t.Fatalf("expected ErrExecutionReverted, got %v", err)
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
	if !errors.Is(err, ErrExecutionReverted) || out[0] != revertWorkflowIDInvalid {
		t.Fatalf("expected 0x06, got %v", out)
	}
}

func TestParseWorkflowID_LengthTooBig(t *testing.T) {
	c := &agnt2Interaction{}
	input := makeInputWithWfID(0x00, "test", 1, int(agnt2LeafSize))
	binary.BigEndian.PutUint32(input[65:69], maxWorkflowIDLen+1) // Corrupt length
	out, err := c.Run(input)
	if !errors.Is(err, ErrExecutionReverted) || out[0] != revertWorkflowIDInvalid {
		t.Fatalf("expected 0x06, got %v", out)
	}
}

func TestParseWorkflowID_NonZeroPadding(t *testing.T) {
	c := &agnt2Interaction{}
	input := makeInputWithWfID(0x00, "test", 1, int(agnt2LeafSize))
	input[69+4] = 0xFF // Corrupt padding
	out, err := c.Run(input)
	if !errors.Is(err, ErrExecutionReverted) || out[0] != revertWorkflowIDInvalid {
		t.Fatalf("expected 0x06, got %v", out)
	}
}

func TestParseWorkflowID_TrailingBytes(t *testing.T) {
	c := &agnt2Interaction{}
	input := makeInputWithWfID(0x00, "test", 1, int(agnt2LeafSize))
	input = append(input, 0x00) // extra byte
	out, err := c.Run(input)
	if !errors.Is(err, ErrExecutionReverted) || out[0] != revertMalformedCalldata {
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
	if !errors.Is(err, ErrExecutionReverted) || len(out) == 0 || out[0] != revertWorkflowIDInvalid {
		t.Fatalf("expected 0x06, got %v", out)
	}
}

func TestParseWorkflowID_TooShortForHeader(t *testing.T) {
	c := &agnt2Interaction{}
	input := make([]byte, 69)
	input[0] = 0x00 // version
	// length field implicitly 0 (all zeroes)
	out, err := c.Run(input)
	if !errors.Is(err, ErrExecutionReverted) || len(out) == 0 || out[0] != revertWorkflowIDInvalid {
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

// Phase 5 MMR wire up: stepCount > 0 now succeeds.
func TestRun_OneStepSuccess(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 1)
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if err != nil || out != nil {
		t.Fatalf("expected success; got err=%v, out=%v", err, out)
	}
}

// Sweep stepCount=1..1000 to confirm Phase 5 accepts valid inputs.
func TestRun_StepCountSweep_Success(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-sweep"
	expectedHash := crypto.Keccak256([]byte(wfID))
	for _, stepCount := range []uint32{1, 2, 10, 100, 1000} {
		leaves := makeChainedLeaves(expectedHash, int(stepCount))
		input := makeInputWithLeaves(wfID, leaves)
		out, err := c.Run(input)
		if err != nil || out != nil {
			t.Fatalf("stepCount=%d: expected success, got err=%v, out=%v", stepCount, err, out)
		}
	}
}

func TestRun_WorkflowBindingValid_OneStep(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 1)
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if err != nil || out != nil {
		t.Fatalf("expected success, got %v, %v", err, out)
	}
}

func TestRun_WorkflowBindingValid_ThreeStep(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 3)
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if err != nil || out != nil {
		t.Fatalf("expected success, got %v, %v", err, out)
	}
}

func TestRun_ChainValid_OneStep(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 1)
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if err != nil || out != nil {
		t.Fatalf("expected success, got %v, %v", err, out)
	}
}

func TestRun_ChainValid_ThreeStep(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 3)
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if err != nil || out != nil {
		t.Fatalf("expected success, got %v, %v", err, out)
	}
}

func TestRun_ChainBrokenAtFirst(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 1)
	leaves[160-1] = 0xFF // corrupt prevLeafHash of leaf[0]
	out, err := c.Run(makeInputWithLeaves(wfID, leaves))
	if !errors.Is(err, ErrExecutionReverted) {
		t.Fatalf("expected ErrExecutionReverted, got %v", err)
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
	if !errors.Is(err, ErrExecutionReverted) {
		t.Fatalf("expected ErrExecutionReverted, got %v", err)
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
	if !errors.Is(err, ErrExecutionReverted) {
		t.Fatalf("expected ErrExecutionReverted, got %v", err)
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
	if !errors.Is(err, ErrExecutionReverted) {
		t.Fatalf("expected ErrExecutionReverted, got %v", err)
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
	if !errors.Is(err, ErrExecutionReverted) {
		t.Fatalf("expected ErrExecutionReverted, got %v", err)
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
	if !errors.Is(err, ErrExecutionReverted) {
		t.Fatalf("expected ErrExecutionReverted, got %v", err)
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
	if !errors.Is(err, ErrExecutionReverted) {
		t.Fatalf("expected ErrExecutionReverted, got %v", err)
	}
	if len(out) != 1 || out[0] != revertWorkflowBindingMismatch {
		t.Fatalf("expected revertWorkflowBindingMismatch (0x07), got %v", out)
	}
}

func TestRequiredGas_BindingMismatch_FullStepGas(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-wf-001"
	wrongHash := crypto.Keccak256([]byte("test-wf-002"))
	leaves := make([]byte, 0, 100*160)
	for i := 0; i < 100; i++ {
		leaves = append(leaves, makeLeaf(wrongHash, 0xAA)...)
	}
	input := makeInputWithLeaves(wfID, leaves)

	gas := c.RequiredGas(input)
	expectedGas := params.AGNT2BaseGas + 100*params.AGNT2PerStepGas
	if gas != expectedGas {
		t.Fatalf("RequiredGas: want %d (full step gas — binding mismatch is semantic, not syntactic), got %d", expectedGas, gas)
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
			if !errors.Is(err, ErrExecutionReverted) {
				t.Fatalf("expected ErrExecutionReverted; got %v", err)
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
	if !errors.Is(err, ErrExecutionReverted) {
		t.Fatalf("expected ErrExecutionReverted; got %v", err)
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
	if !errors.Is(err, ErrExecutionReverted) {
		t.Fatalf("expected ErrExecutionReverted; got %v", err)
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
		{"valid 1 step", makeInputWithLeaves("test-wf", makeChainedLeaves(crypto.Keccak256([]byte("test-wf")), 1)), params.AGNT2BaseGas + 1*params.AGNT2PerStepGas},
		{"valid 100 steps", makeInputWithLeaves("test-wf", makeChainedLeaves(crypto.Keccak256([]byte("test-wf")), 100)), params.AGNT2BaseGas + 100*params.AGNT2PerStepGas},
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
// Phase 5: Loops over all valid stepCounts.
func TestRequiredGas_Run_AcceptanceInvariant(t *testing.T) {
	c := &agnt2Interaction{}
	wfID := "test-sweep"
	expectedHash := crypto.Keccak256([]byte(wfID))
	for _, stepCount := range []uint32{0, 1, 2, 10, 100, 1000} {
		var input []byte
		if stepCount == 0 {
			input = makeInput(0x00, 0, 0)
		} else {
			input = makeInputWithLeaves(wfID, makeChainedLeaves(expectedHash, int(stepCount)))
		}
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

// --- MMR Phase 5 Tests ---

func makeCanonicalChain(workflowID string, steps []struct {
	stepID, agentRole string
	payout            uint64
}) [][]byte {
	leaves := make([][]byte, len(steps))
	var prevHash [32]byte

	for i, step := range steps {
		var buf []byte
		buf = append(buf, crypto.Keccak256Hash([]byte(workflowID)).Bytes()...)
		buf = append(buf, crypto.Keccak256Hash([]byte(step.stepID)).Bytes()...)
		buf = append(buf, crypto.Keccak256Hash([]byte(step.agentRole)).Bytes()...)

		padded := make([]byte, 32)
		binary.BigEndian.PutUint64(padded[24:32], step.payout)
		buf = append(buf, padded...)
		buf = append(buf, prevHash[:]...)

		leaves[i] = buf
		prevHash = crypto.Keccak256Hash(buf)
	}
	return leaves
}

func TestRun_MMRRoot_v1_3step(t *testing.T) {
	wfID := "test-wf-001"
	steps := []struct {
		stepID, agentRole string
		payout            uint64
	}{
		{"step-1", "worker-a", 1000},
		{"step-2", "worker-b", 2000},
		{"step-3", "worker-c", 3000},
	}
	leavesBytes := makeCanonicalChain(wfID, steps)
	var flat []byte
	for _, l := range leavesBytes {
		flat = append(flat, l...)
	}

	input := makeInputWithLeaves(wfID, flat)
	// Re-derive stepCount, abiHeaderSize, workflowID for the helper call
	stepCount := uint64(binary.BigEndian.Uint32(input[1:5]))
	workflowIDParsed, abiHeaderSize, _ := parseWorkflowID(input)

	root, _, errCode := validateAndBuildMMR(input, stepCount, abiHeaderSize, workflowIDParsed)
	if errCode != 0 {
		t.Fatalf("validateAndBuildMMR returned error byte 0x%02x", errCode)
	}
	expectedBytes, _ := hex.DecodeString("d54c19717603e20fbf82ff44e90eafd7d1ad14ef4d7811f8802cc3c078cc86c3")
	var expected [32]byte
	copy(expected[:], expectedBytes)

	if !bytes.Equal(root[:], expected[:]) {
		t.Fatalf("v1_3step MMR root mismatch: want %x, got %x", expected, root)
	}

	// Also verify Run accepts the calldata cleanly (regression check)
	c := &agnt2Interaction{}
	out, err := c.Run(input)
	if err != nil || out != nil {
		t.Fatalf("Run rejected canonical v1_3step calldata: out=%v err=%v", out, err)
	}
}

func TestRun_MMRRoot_v4_5step(t *testing.T) {
	wfID := "test-wf-005"
	steps := []struct {
		stepID, agentRole string
		payout            uint64
	}{
		{"step-1", "worker-a", 1000},
		{"step-2", "worker-b", 2000},
		{"step-3", "worker-c", 3000},
		{"step-4", "worker-d", 4000},
		{"step-5", "worker-e", 5000},
	}
	leavesBytes := makeCanonicalChain(wfID, steps)
	var flat []byte
	for _, l := range leavesBytes {
		flat = append(flat, l...)
	}

	input := makeInputWithLeaves(wfID, flat)
	// Re-derive stepCount, abiHeaderSize, workflowID for the helper call
	stepCount := uint64(binary.BigEndian.Uint32(input[1:5]))
	workflowIDParsed, abiHeaderSize, _ := parseWorkflowID(input)

	root, _, errCode := validateAndBuildMMR(input, stepCount, abiHeaderSize, workflowIDParsed)
	if errCode != 0 {
		t.Fatalf("validateAndBuildMMR returned error byte 0x%02x", errCode)
	}
	expectedBytes, _ := hex.DecodeString("e34cda67eaf574138a02ab6ea87fd1ec55f8e3c09545f2c7c44edb8365316c91")
	var expected [32]byte
	copy(expected[:], expectedBytes)

	if !bytes.Equal(root[:], expected[:]) {
		t.Fatalf("v4_5step MMR root mismatch: want %x, got %x", expected, root)
	}

	// Also verify Run accepts the calldata cleanly (regression check)
	c := &agnt2Interaction{}
	out, err := c.Run(input)
	if err != nil || out != nil {
		t.Fatalf("Run rejected canonical v4_5step calldata: out=%v err=%v", out, err)
	}
}

func TestRun_MMREmpty(t *testing.T) {
	c := &agnt2Interaction{}
	out, err := c.Run(makeInput(0x00, 0, 0))
	if err != nil || out != nil {
		t.Fatalf("expected success, got err=%v, out=%v", err, out)
	}

	m := &agnt2MMR{}
	root := m.getRoot()
	expectedBytes, _ := hex.DecodeString("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
	var expected [32]byte
	copy(expected[:], expectedBytes)

	if !bytes.Equal(root[:], expected[:]) {
		t.Fatalf("empty MMR root mismatch: want %x, got %x", expected, root)
	}
}

func TestAgnt2MMR_BuildTreeMatches_TS(t *testing.T) {
	var leaves [][32]byte
	for i := 0; i < 3; i++ {
		var l [32]byte
		l[0] = byte(i + 1)
		leaves = append(leaves, l)
	}
	m := &agnt2MMR{leaves: leaves}
	root := m.getRoot()

	var p0_combined [64]byte
	copy(p0_combined[0:32], leaves[0][:])
	copy(p0_combined[32:64], leaves[1][:])
	var peak0 [32]byte
	copy(peak0[:], crypto.Keccak256(p0_combined[:]))

	var final_combined [64]byte
	copy(final_combined[0:32], peak0[:])
	copy(final_combined[32:64], leaves[2][:])
	var expectedRoot [32]byte
	copy(expectedRoot[:], crypto.Keccak256(final_combined[:]))

	if !bytes.Equal(root[:], expectedRoot[:]) {
		t.Fatalf("build tree fold mismatch: want %x, got %x", expectedRoot, root)
	}
}

// --- Root Hook Phase 6 Tests ---

func TestRootHook_v1_3step_PublishedAfterRun(t *testing.T) {
	wfID := "test-wf-001"
	steps := []struct {
		stepID, agentRole string
		payout            uint64
	}{
		{"step-1", "worker-a", 1000},
		{"step-2", "worker-b", 2000},
		{"step-3", "worker-c", 3000},
	}
	leavesBytes := makeCanonicalChain(wfID, steps)
	var flat []byte
	for _, l := range leavesBytes {
		flat = append(flat, l...)
	}

	input := makeInputWithLeaves(wfID, flat)
	c := &agnt2Interaction{}

	_, err := c.Run(input)
	if err != nil {
		t.Fatalf("Run rejected canonical v1_3step calldata")
	}

	root, set := GetInteractionRoot()
	if !set {
		t.Fatalf("GetInteractionRoot() returned set=false after successful Run")
	}

	expectedBytes, _ := hex.DecodeString("d54c19717603e20fbf82ff44e90eafd7d1ad14ef4d7811f8802cc3c078cc86c3")
	var expected [32]byte
	copy(expected[:], expectedBytes)

	if !bytes.Equal(root[:], expected[:]) {
		t.Fatalf("Root hook MMR mismatch: want %x, got %x", expected, root)
	}
}

func TestRootHook_v4_5step_PublishedAfterRun(t *testing.T) {
	wfID := "test-wf-005"
	steps := []struct {
		stepID, agentRole string
		payout            uint64
	}{
		{"step-1", "worker-a", 1000},
		{"step-2", "worker-b", 2000},
		{"step-3", "worker-c", 3000},
		{"step-4", "worker-d", 4000},
		{"step-5", "worker-e", 5000},
	}
	leavesBytes := makeCanonicalChain(wfID, steps)
	var flat []byte
	for _, l := range leavesBytes {
		flat = append(flat, l...)
	}

	input := makeInputWithLeaves(wfID, flat)
	c := &agnt2Interaction{}

	_, err := c.Run(input)
	if err != nil {
		t.Fatalf("Run rejected canonical v4_5step calldata")
	}

	root, set := GetInteractionRoot()
	if !set {
		t.Fatalf("GetInteractionRoot() returned set=false after successful Run")
	}

	expectedBytes, _ := hex.DecodeString("e34cda67eaf574138a02ab6ea87fd1ec55f8e3c09545f2c7c44edb8365316c91")
	var expected [32]byte
	copy(expected[:], expectedBytes)

	if !bytes.Equal(root[:], expected[:]) {
		t.Fatalf("Root hook MMR mismatch: want %x, got %x", expected, root)
	}
}

func TestRootHook_NotSetUntilFirstRun(t *testing.T) {
	store := &agnt2RootStore{}
	_, set := store.get()
	if set {
		t.Fatalf("fresh store should report set=false")
	}
}

func TestRootHook_FailedRunDoesNotUpdate(t *testing.T) {
	// Record current global state
	beforeRoot, beforeSet := GetInteractionRoot()

	// Make a failing run call
	c := &agnt2Interaction{}
	// Bad version byte
	input := makeInput(0x01, 1000, 160000)
	c.Run(input)

	afterRoot, afterSet := GetInteractionRoot()
	if beforeSet != afterSet || !bytes.Equal(beforeRoot[:], afterRoot[:]) {
		t.Fatalf("Failed Run altered the global root store state. Before: %x (%v), After: %x (%v)", beforeRoot, beforeSet, afterRoot, afterSet)
	}
}

func TestRootHook_Concurrency(t *testing.T) {
	var wg sync.WaitGroup
	wfID := "test-wf-001"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 1)
	input := makeInputWithLeaves(wfID, leaves)
	c := &agnt2Interaction{}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Run(input)
			GetInteractionRoot()
		}()
	}
	wg.Wait()
}

// TestRootHook_ScaffoldOnly_NotBlockSafe documents the known scaffold
// limitation: two sequential Run() calls overwrite the same root, with
// no per-block isolation. This test LOCKS the limitation so anyone
// removing the warning without doing the Week 11 architectural fix
// will fail this test.
func TestRootHook_ScaffoldOnly_NotBlockSafe(t *testing.T) {
	c := &agnt2Interaction{}
	wfA := "block-a-wf"
	wfB := "block-b-wf"

	// Submit block A's calldata
	leavesA := makeChainedLeaves(crypto.Keccak256([]byte(wfA)), 1)
	inputA := makeInputWithLeaves(wfA, leavesA)
	if _, err := c.Run(inputA); err != nil {
		t.Fatalf("block A run failed: %v", err)
	}
	rootA, _ := GetInteractionRoot()

	// Submit block B's calldata — this OVERWRITES block A's root in the
	// global store. Week 11 must replace this with per-block isolation.
	leavesB := makeChainedLeaves(crypto.Keccak256([]byte(wfB)), 1)
	inputB := makeInputWithLeaves(wfB, leavesB)
	if _, err := c.Run(inputB); err != nil {
		t.Fatalf("block B run failed: %v", err)
	}
	rootB, _ := GetInteractionRoot()

	// The roots must differ (different workflow IDs produce different
	// leaf hashes), and the global now holds B's root, not A's.
	if rootA == rootB {
		t.Fatalf("rootA and rootB unexpectedly equal — test fixtures broken")
	}
	// After block B's call, GetInteractionRoot returns B's root, NOT A's.
	// This is the documented Week 10 scaffold behavior.
	if currentRoot, _ := GetInteractionRoot(); currentRoot != rootB {
		t.Fatalf("expected current root to equal rootB; scaffold semantic broken")
	}
}

// --- Phase 7 Leaf Events Tests ---

func TestLeafEvents_OneStepEmission(t *testing.T) {
	t.Cleanup(globalAgnt2EventStore.reset)
	globalAgnt2EventStore.reset()

	c := &agnt2Interaction{}
	wfID := "test-event-1"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 1)

	input := makeInputWithLeaves(wfID, leaves)
	if _, err := c.Run(input); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	events := LastEmittedEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	e := events[0]
	if e.StepIndex != 0 {
		t.Fatalf("expected StepIndex 0, got %d", e.StepIndex)
	}
	var expectedWfHash, expectedStepID, expectedAgentRole, expectedLeafHash [32]byte
	copy(expectedWfHash[:], expectedHash)
	copy(expectedStepID[:], leaves[32:64])
	copy(expectedAgentRole[:], leaves[64:96])
	copy(expectedLeafHash[:], crypto.Keccak256(leaves))
	if e.WorkflowIDHash != expectedWfHash {
		t.Fatalf("WorkflowIDHash mismatch")
	}
	if e.StepIDHash != expectedStepID {
		t.Fatalf("StepIDHash mismatch: got %x, want %x", e.StepIDHash, expectedStepID)
	}
	if e.AgentRoleHash != expectedAgentRole {
		t.Fatalf("AgentRoleHash mismatch: got %x, want %x", e.AgentRoleHash, expectedAgentRole)
	}
	if e.LeafHash != expectedLeafHash {
		t.Fatalf("LeafHash mismatch")
	}
	if e.Payout[31] != 1 {
		t.Fatalf("Payout mismatch, expected 1 in low byte, got %d", e.Payout[31])
	}
}

func TestLeafEvents_ThreeStepOrder(t *testing.T) {
	t.Cleanup(globalAgnt2EventStore.reset)
	globalAgnt2EventStore.reset()

	c := &agnt2Interaction{}
	wfID := "test-event-3"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 3)

	input := makeInputWithLeaves(wfID, leaves)
	if _, err := c.Run(input); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	events := LastEmittedEvents()
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	for i, e := range events {
		if e.StepIndex != uint32(i) {
			t.Fatalf("expected StepIndex %d, got %d", i, e.StepIndex)
		}
		var wantStepID, wantAgentRole [32]byte
		copy(wantStepID[:], leaves[i*160+32:i*160+64])
		copy(wantAgentRole[:], leaves[i*160+64:i*160+96])
		if e.StepIDHash != wantStepID {
			t.Fatalf("event[%d] StepIDHash mismatch", i)
		}
		if e.AgentRoleHash != wantAgentRole {
			t.Fatalf("event[%d] AgentRoleHash mismatch", i)
		}
	}
}

// TestLeafEvents_FailedCallPreservesPriorEvents documents the commit-on-success
// semantic: a successful call commits its events to the singleton; a subsequent
// failing call MUST leave those events untouched. This mirrors the EVM log
// journal — a reverted call's logs are dropped, and prior calls' logs remain
// visible to consumers calling LastEmittedEvents().
func TestLeafEvents_FailedCallPreservesPriorEvents(t *testing.T) {
	t.Cleanup(globalAgnt2EventStore.reset)
	globalAgnt2EventStore.reset()

	c := &agnt2Interaction{}
	wfID := "test-event-preserve"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 3)

	if _, err := c.Run(makeInputWithLeaves(wfID, leaves)); err != nil {
		t.Fatalf("first Run failed: %v", err)
	}
	if got := len(LastEmittedEvents()); got != 3 {
		t.Fatalf("expected 3 events after success, got %d", got)
	}

	// Submit malformed call (bad version) — must NOT clobber prior events.
	badInput := makeInput(0x01, 1000, 160000)
	if _, err := c.Run(badInput); err == nil {
		t.Fatalf("expected malformed call to revert")
	}

	eventsAfter := LastEmittedEvents()
	if len(eventsAfter) != 3 {
		t.Fatalf("commit-on-success violated: expected prior 3 events to persist after failed run, got %d", len(eventsAfter))
	}
}

// TestLeafEvents_FailedRunHasNoEvents covers the inverse: a chain-break
// mid-loop must NOT leak partial events. validateAndBuildMMR returns nil
// events on revert and Run() never calls commit, so the singleton's prior
// state (here: empty) is preserved.
func TestLeafEvents_FailedRunHasNoEvents(t *testing.T) {
	t.Cleanup(globalAgnt2EventStore.reset)
	globalAgnt2EventStore.reset()

	c := &agnt2Interaction{}
	wfID := "test-event-chainbreak"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 3)

	// Corrupt leaf 1's prevLeafHash to break chain at step 1
	leaves[160+160-1] = 0xFF

	input := makeInputWithLeaves(wfID, leaves)
	_, err := c.Run(input)
	if !errors.Is(err, ErrExecutionReverted) {
		t.Fatalf("expected ErrExecutionReverted, got %v", err)
	}

	events := LastEmittedEvents()
	if len(events) != 0 {
		t.Fatalf("expected 0 events after chain-break revert (commit-on-success), got %d", len(events))
	}
}

func TestLeafEvents_StepCountZero_NoEvents(t *testing.T) {
	t.Cleanup(globalAgnt2EventStore.reset)
	globalAgnt2EventStore.reset()

	c := &agnt2Interaction{}
	input := makeInput(0x00, 0, 0)
	if _, err := c.Run(input); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	events := LastEmittedEvents()
	if len(events) != 0 {
		t.Fatalf("expected 0 events for zero steps, got %d", len(events))
	}
}

// TestLeafEvents_Concurrency runs N successful Run() calls in parallel
// where each goroutine uses a distinct wfID. The final snapshot must
// contain stepCount events all bound to a single wfID — proving the
// commit() replace-in-place is atomic and the snapshot is not a torn
// mix from multiple commits. Race detector also checks read/write races.
func TestLeafEvents_Concurrency(t *testing.T) {
	t.Cleanup(globalAgnt2EventStore.reset)
	globalAgnt2EventStore.reset()

	const goroutines = 16
	const stepCount = 4

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			c := &agnt2Interaction{}
			wfID := fmt.Sprintf("test-event-conc-%d", g)
			expectedHash := crypto.Keccak256([]byte(wfID))
			leaves := makeChainedLeaves(expectedHash, stepCount)
			if _, err := c.Run(makeInputWithLeaves(wfID, leaves)); err != nil {
				t.Errorf("Run failed: %v", err)
			}
		}()
	}
	wg.Wait()

	events := LastEmittedEvents()
	if len(events) != stepCount {
		t.Fatalf("expected store length %d after concurrent commits, got %d", stepCount, len(events))
	}
	// All events in the final snapshot must share the same WorkflowIDHash
	// (the winning writer) — a torn commit would mix two writers' events.
	winnerHash := events[0].WorkflowIDHash
	for i, e := range events {
		if e.StepIndex != uint32(i) {
			t.Fatalf("event[%d] StepIndex %d (likely torn snapshot)", i, e.StepIndex)
		}
		if e.WorkflowIDHash != winnerHash {
			t.Fatalf("event[%d] WorkflowIDHash differs from event[0] — torn commit detected", i)
		}
	}
}
