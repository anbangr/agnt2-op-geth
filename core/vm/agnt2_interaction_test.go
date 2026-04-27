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
			// Direct equality (not errors.Is) — this is what op-geth's evm.go:331
			// uses to decide gas-refund-on-revert vs all-gas-consumed. Wrapping
			// would silently flip the contract documented in this file's revert
			// codes table; pinning direct equality here is the load-bearing
			// guard for ADR 002 §Revert Error Codes.
			if err != ErrExecutionReverted {
				t.Fatalf("expected vm.ErrExecutionReverted (direct ==); got %v", err)
			}
			if len(out) != 1 || out[0] != tc.wantCode {
				t.Fatalf("expected revert code 0x%02x; got %v", tc.wantCode, out)
			}
		})
	}
}

// TestRun_StepOverflow_OperationalCap exercises the Phase 3 operational cap
// (params.AGNT2MaxStepsPerCall = 10_000). stepCount = cap + 1 must revert
// with revertStepOverflow (0x03) — the same byte the wrap protector uses,
// because on-chain decoders need not distinguish operational vs wrap rejection.
func TestRun_StepOverflow_OperationalCap(t *testing.T) {
	c := &agnt2Interaction{}
	overflow := uint32(params.AGNT2MaxStepsPerCall + 1)
	input := makeInput(0x00, overflow, 0)
	out, err := c.Run(input)
	if err != ErrExecutionReverted {
		t.Fatalf("expected ErrExecutionReverted (direct ==); got %v", err)
	}
	if len(out) != 1 || out[0] != revertStepOverflow {
		t.Fatalf("expected revertStepOverflow; got 0x%02x", out[0])
	}
}

// TestRun_StepOverflow_WrapProtector_Unreachable documents that the wrap
// protector (maxSafeLeafCount = 26_843_545) is logically dead under the
// operational cap (10_000 < 26M). Pinning the unreachable check here so
// future edits to AGNT2MaxStepsPerCall that lift it above maxSafeLeafCount
// don't silently disable the wrap protector. Sending stepCount = wrap+1
// still gets caught — but by the operational cap first; we observe the
// same revert byte either way.
func TestRun_StepOverflow_WrapProtector_Unreachable(t *testing.T) {
	c := &agnt2Interaction{}
	beyond := uint32(maxSafeLeafCount + 1) // > both caps
	input := makeInput(0x00, beyond, 0)
	out, err := c.Run(input)
	if err != ErrExecutionReverted {
		t.Fatalf("expected ErrExecutionReverted (direct ==); got %v", err)
	}
	if len(out) != 1 || out[0] != revertStepOverflow {
		t.Fatalf("expected revertStepOverflow; got 0x%02x", out[0])
	}
	// Defense-in-depth invariant: operational cap must be < wrap protector.
	if params.AGNT2MaxStepsPerCall >= maxSafeLeafCount {
		t.Fatalf("operational cap (%d) must be strictly less than wrap protector (%d)",
			params.AGNT2MaxStepsPerCall, maxSafeLeafCount)
	}
}

// TestRun_BoundaryAtMaxStepsPerCall pins the inclusive boundary of the Phase 3
// operational cap. stepCount = AGNT2MaxStepsPerCall must NOT trigger
// STEP_OVERFLOW (the comparison is `>`, not `>=`). Sending only the header
// surfaces MALFORMED instead — same semantic as the prior wrap-protector
// boundary test, but now anchored at the operational cap (10_000) instead
// of the unreachable wrap protector (26_843_545).
func TestRun_BoundaryAtMaxStepsPerCall(t *testing.T) {
	c := &agnt2Interaction{}
	atCap := uint32(params.AGNT2MaxStepsPerCall)
	input := makeInput(0x00, atCap, 0)
	out, err := c.Run(input)
	if err != ErrExecutionReverted {
		t.Fatalf("expected ErrExecutionReverted (direct ==); got %v", err)
	}
	if len(out) != 1 || out[0] != revertMalformedCalldata {
		t.Fatalf("at AGNT2MaxStepsPerCall, expected revertMalformedCalldata; got 0x%02x", out[0])
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
		{"operational-cap exceeded -> base only", makeInput(0x00, uint32(params.AGNT2MaxStepsPerCall+1), 0), params.AGNT2BaseGas},
		{"wrap-protector exceeded -> base only", makeInput(0x00, uint32(maxSafeLeafCount+1), 0), params.AGNT2BaseGas},
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
		makeInput(0x00, uint32(params.AGNT2MaxStepsPerCall+1), 0), // operational cap exceeded
		makeInput(0x00, uint32(maxSafeLeafCount+1), 0),            // wrap protector exceeded
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

// TestStepCountCaps_Bounds pins the literal values of both step-count caps:
// (a) maxSafeLeafCount = 26_843_545 — uint32-overflow wrap protector
// (b) params.AGNT2MaxStepsPerCall = 4_500 — operational cap (Week 11 Phase 6;
//     tightened from 10_000 to absorb the per-leaf LOG cost added when log
//     emission moved from a singleton to stateDB.AddLog via the dispatch
//     post-hook).
//
// Invariants:
//   - Wrap protector must continue to satisfy the uint32 fit (load-bearing
//     for 32-bit Go builds).
//   - Operational cap must be strictly LESS than the wrap protector — if
//     these are ever inverted, the wrap protector becomes reachable and the
//     defense-in-depth ordering in Run/RequiredGas breaks. This is the
//     guard the Phase 3 plan §"defense-in-depth" comment depends on.
//   - Operational cap × per-step gas + base gas must leave ≥30% headroom under
//     a 30M block gas limit (Phase 6 derivation).
func TestStepCountCaps_Bounds(t *testing.T) {
	if maxSafeLeafCount != 26_843_545 {
		t.Fatalf("maxSafeLeafCount changed: want 26_843_545, got %d", maxSafeLeafCount)
	}
	if maxSafeLeafCount*agnt2LeafSize > uint64(^uint32(0)) {
		t.Fatalf("maxSafeLeafCount*leafSize must fit in uint32; got %d", maxSafeLeafCount*agnt2LeafSize)
	}
	if (maxSafeLeafCount+1)*agnt2LeafSize <= uint64(^uint32(0)) {
		t.Fatalf("(maxSafeLeafCount+1)*leafSize must exceed uint32; got %d", (maxSafeLeafCount+1)*agnt2LeafSize)
	}
	if params.AGNT2MaxStepsPerCall != 4_500 {
		t.Fatalf("AGNT2MaxStepsPerCall changed: want 4_500, got %d", params.AGNT2MaxStepsPerCall)
	}
	if params.AGNT2MaxStepsPerCall >= maxSafeLeafCount {
		t.Fatalf("ordering invariant broken: operational cap (%d) must be < wrap protector (%d)",
			params.AGNT2MaxStepsPerCall, maxSafeLeafCount)
	}
	// 30M block gas budget × 70% = 21M usable per call.
	const blockGasBudget = uint64(30_000_000)
	const headroomFraction = uint64(70) // permille / 100; using integer math
	maxAllowedCallGas := blockGasBudget * headroomFraction / 100
	worstCaseCallGas := params.AGNT2BaseGas + params.AGNT2MaxStepsPerCall*params.AGNT2PerStepGas
	if worstCaseCallGas > maxAllowedCallGas {
		t.Fatalf("AGNT2 worst-case call gas %d exceeds 70%% of 30M block (%d) — re-derive cap",
			worstCaseCallGas, maxAllowedCallGas)
	}
}

// TestPerStepGas_LogCostAccounted pins the Phase 6 per-step gas derivation:
// AGNT2PerStepGas must include the LOG cost (375 base + 2 topics × 375 +
// 160 data bytes × 8 = 2_405) on top of the Run() validation cost (2_000).
// If the LOG cost is ever stripped without re-deriving the cap, this test
// fires before the silent under-billing of an emitted log.
func TestPerStepGas_LogCostAccounted(t *testing.T) {
	const runValidationCost = uint64(2_000)
	const logBaseCost = params.LogGas
	const logTopicCost = uint64(2) * params.LogTopicGas
	const logDataCost = uint64(160) * params.LogDataGas
	expected := runValidationCost + logBaseCost + logTopicCost + logDataCost
	if params.AGNT2PerStepGas != expected {
		t.Fatalf("AGNT2PerStepGas %d != expected %d (run %d + LogGas %d + 2×LogTopicGas %d + 160×LogDataGas %d)",
			params.AGNT2PerStepGas, expected, runValidationCost, logBaseCost, logTopicCost, logDataCost)
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

// --- Root Hook Phase 7 Replacement Tests ---
//
// Week 11 Phase 7 removed the package-level globalAgnt2RootStore singleton
// (Week 10 scaffold) in favour of receipt-derived MMR folds via
// core/types.FoldInteractionRoot, committed in fork-gated Header fields and
// validated at block import. The tests below pin the contract that Run()
// no longer mutates any package-level state, and that successful runs are
// observable purely via the agnt2ParseLeaves shared helper which both Run
// and the post-success log dispatcher route through.

// TestRun_NoPackageLevelStateMutation locks the Phase 7 contract: Run()
// must produce identical (root, events, errCode) outputs across repeated
// calls, with no carry-over via globals. Two different workflows give two
// different roots; Run does not "remember" the previous one. (The Week 10
// scaffold's TestRootHook_ScaffoldOnly_NotBlockSafe documented exactly the
// opposite — that scaffold is now gone.)
func TestRun_NoPackageLevelStateMutation(t *testing.T) {
	c := &agnt2Interaction{}
	wfA := "block-a-wf"
	wfB := "block-b-wf"

	leavesA := makeChainedLeaves(crypto.Keccak256([]byte(wfA)), 1)
	inputA := makeInputWithLeaves(wfA, leavesA)
	if _, err := c.Run(inputA); err != nil {
		t.Fatalf("block A run failed: %v", err)
	}
	rootA, _, errA := agnt2ParseLeaves(inputA)
	if errA != 0 {
		t.Fatalf("parse A unexpectedly failed: 0x%02x", errA)
	}

	leavesB := makeChainedLeaves(crypto.Keccak256([]byte(wfB)), 1)
	inputB := makeInputWithLeaves(wfB, leavesB)
	if _, err := c.Run(inputB); err != nil {
		t.Fatalf("block B run failed: %v", err)
	}
	rootB, _, errB := agnt2ParseLeaves(inputB)
	if errB != 0 {
		t.Fatalf("parse B unexpectedly failed: 0x%02x", errB)
	}

	if bytes.Equal(rootA[:], rootB[:]) {
		t.Fatalf("rootA and rootB unexpectedly equal — test fixtures broken")
	}

	// Re-parse A: must give the same rootA — proving Run() left no
	// package-level state behind that would corrupt subsequent parses.
	rootA2, _, _ := agnt2ParseLeaves(inputA)
	if !bytes.Equal(rootA[:], rootA2[:]) {
		t.Fatalf("re-parse of inputA produced a different root: first=%x second=%x", rootA, rootA2)
	}
}

// TestRun_ConcurrencySafe re-asserts the goroutine-safety property after
// removing the singleton: the precompile is fully stateless across
// concurrent invocations.
func TestRun_ConcurrencySafe(t *testing.T) {
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
		}()
	}
	wg.Wait()
}

// --- Phase 6 Leaf-Event Parser Tests ---
//
// Phase 6 replaced the singleton globalAgnt2EventStore with stateDB.AddLog
// emission via the EVM dispatch post-hook (evmAGNT2PostHook). The shared
// parser helper agnt2ParseLeaves remains the single source of truth for
// "what events would be emitted given this calldata"; these tests pin the
// parser's event-shape contract directly. The full dispatch-path tests
// that observe real receipt logs live in agnt2_dispatch_logs_test.go.

func TestLeafEventParser_OneStep(t *testing.T) {
	wfID := "test-event-1"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 1)

	input := makeInputWithLeaves(wfID, leaves)
	_, events, errCode := agnt2ParseLeaves(input)
	if errCode != 0 {
		t.Fatalf("parse failed with errCode 0x%02x", errCode)
	}
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

func TestLeafEventParser_ThreeStepOrder(t *testing.T) {
	wfID := "test-event-3"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 3)

	input := makeInputWithLeaves(wfID, leaves)
	_, events, errCode := agnt2ParseLeaves(input)
	if errCode != 0 {
		t.Fatalf("parse failed with errCode 0x%02x", errCode)
	}
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

// TestLeafEventParser_FailedCallEmitsNoEvents covers the parser's
// commit-on-success contract: a parse that fails (any errCode != 0)
// MUST return events == nil so the dispatcher's emit loop has nothing to
// fold into stateDB.AddLog. The pre-Phase-6 commit-on-success singleton
// behavior is now provided by the dispatcher itself: the post-hook only
// invokes agnt2EmitLogs when err == nil from RunPrecompiledContract.
func TestLeafEventParser_FailedParseEmitsNoEvents(t *testing.T) {
	cases := []struct {
		name     string
		input    []byte
		wantCode byte
	}{
		{"bad version", makeInput(0x01, 1000, 160000), revertInvalidVersion},
		{"step overflow", makeInput(0x00, uint32(params.AGNT2MaxStepsPerCall+1), 0), revertStepOverflow},
		{"malformed length", makeInput(0x00, 1, 159), revertMalformedCalldata},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, events, errCode := agnt2ParseLeaves(tc.input)
			if errCode != tc.wantCode {
				t.Fatalf("expected errCode 0x%02x, got 0x%02x", tc.wantCode, errCode)
			}
			if len(events) != 0 {
				t.Fatalf("expected 0 events on failed parse, got %d", len(events))
			}
		})
	}
}

// TestLeafEventParser_ChainBrokenEmitsNoPartialEvents covers the inverse:
// a chain-break mid-loop must NOT leak partial events. validateAndBuildMMR
// returns nil events on the first invalid leaf — the dispatcher's emit
// loop sees zero events and emits nothing.
func TestLeafEventParser_ChainBrokenEmitsNoPartialEvents(t *testing.T) {
	wfID := "test-event-chainbreak"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, 3)
	// Corrupt leaf 1's prevLeafHash to break chain at step 1.
	leaves[160+160-1] = 0xFF

	input := makeInputWithLeaves(wfID, leaves)
	_, events, errCode := agnt2ParseLeaves(input)
	if errCode != revertLeafChainBroken {
		t.Fatalf("expected revertLeafChainBroken (0x08), got 0x%02x", errCode)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events on chain-break, got %d (would leak partial state)", len(events))
	}
}

func TestLeafEventParser_StepCountZero_NoEvents(t *testing.T) {
	input := makeInput(0x00, 0, 0)
	_, events, errCode := agnt2ParseLeaves(input)
	if errCode != 0 {
		t.Fatalf("zero-step parse failed: 0x%02x", errCode)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events for zero steps, got %d", len(events))
	}
}

// TestLeafEventParser_DeterministicConcurrent runs the parser in parallel
// across distinct workflow IDs and asserts each goroutine sees a result
// bound to its own input — the parser is pure, so the race detector is
// the load-bearing assertion here.
func TestLeafEventParser_DeterministicConcurrent(t *testing.T) {
	const goroutines = 16
	const stepCount = 4

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			wfID := fmt.Sprintf("test-event-conc-%d", g)
			expectedHash := crypto.Keccak256([]byte(wfID))
			leaves := makeChainedLeaves(expectedHash, stepCount)
			_, events, errCode := agnt2ParseLeaves(makeInputWithLeaves(wfID, leaves))
			if errCode != 0 {
				t.Errorf("g=%d parse errCode 0x%02x", g, errCode)
				return
			}
			if len(events) != stepCount {
				t.Errorf("g=%d expected %d events, got %d", g, stepCount, len(events))
				return
			}
			var wantWf [32]byte
			copy(wantWf[:], expectedHash)
			for i, e := range events {
				if e.WorkflowIDHash != wantWf {
					t.Errorf("g=%d event[%d] wfHash mismatch (parser leaked across goroutines)", g, i)
					return
				}
				if e.StepIndex != uint32(i) {
					t.Errorf("g=%d event[%d] StepIndex %d", g, i, e.StepIndex)
					return
				}
			}
		}()
	}
	wg.Wait()
}
