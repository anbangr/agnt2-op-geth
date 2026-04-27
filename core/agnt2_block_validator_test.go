package core

import (
	"encoding/binary"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// AGNT2 Week 11 Phase 7 — block-import validation for the
// (InteractionRoot, InteractionCount) header fields.

// TestValidateAGNT2InteractionFields_HappyPath: a header that declares
// values matching the receipt-derived fold passes validation.
func TestValidateAGNT2InteractionFields_HappyPath(t *testing.T) {
	leaf := mustMakeLeaf("test-wf", "step-1", "role-1", big.NewInt(1000), [32]byte{})
	receipts := []*types.Receipt{{Logs: []*types.Log{makeAgnt2LeafLog(0, leaf)}}}

	wantRoot, wantCount := types.FoldInteractionRoot(receipts)
	header := &types.Header{InteractionRoot: &wantRoot, InteractionCount: &wantCount}

	if err := validateAGNT2InteractionFields(header, receipts); err != nil {
		t.Fatalf("happy-path validation failed: %v", err)
	}
}

// TestValidateAGNT2InteractionFields_AbsentFields_NoOp: a pre-fork header
// with both fields nil skips the validation cleanly. This is the path
// taken by every block on chains where AGNT2 has not yet activated.
func TestValidateAGNT2InteractionFields_AbsentFields_NoOp(t *testing.T) {
	header := &types.Header{} // both fields nil
	receipts := []*types.Receipt{}

	if err := validateAGNT2InteractionFields(header, receipts); err != nil {
		t.Fatalf("absent-field validation should be a no-op, got: %v", err)
	}
}

// TestValidateAGNT2InteractionFields_PartialPresence_Rejects: a header
// that sets ONE but not BOTH fields is malformed. Catches the inconsistent
// sequencer state that would otherwise produce silent fold mismatches
// downstream.
func TestValidateAGNT2InteractionFields_PartialPresence_Rejects(t *testing.T) {
	root := common.HexToHash("0x" + strings.Repeat("ab", 32))
	count := uint64(1)

	t.Run("RootOnly", func(t *testing.T) {
		h := &types.Header{InteractionRoot: &root}
		if err := validateAGNT2InteractionFields(h, nil); err == nil {
			t.Fatalf("expected error for root-only header")
		}
	})
	t.Run("CountOnly", func(t *testing.T) {
		h := &types.Header{InteractionCount: &count}
		if err := validateAGNT2InteractionFields(h, nil); err == nil {
			t.Fatalf("expected error for count-only header")
		}
	})
}

// TestValidateAGNT2InteractionFields_SequencerMisbehavior_WrongRoot is
// the load-bearing reject path: a sequencer that declares an arbitrary
// root in the header (not derived from receipts) MUST be rejected at
// block import. This is what stops a malicious sequencer from publishing
// a settled MMR root that doesn't match the actual on-chain interactions.
func TestValidateAGNT2InteractionFields_SequencerMisbehavior_WrongRoot(t *testing.T) {
	leaf := mustMakeLeaf("test-wf", "step-1", "role-1", big.NewInt(1000), [32]byte{})
	receipts := []*types.Receipt{{Logs: []*types.Log{makeAgnt2LeafLog(0, leaf)}}}

	correctRoot, correctCount := types.FoldInteractionRoot(receipts)

	// Tamper the root — a single byte flip is enough.
	tamperedRoot := correctRoot
	tamperedRoot[0] ^= 0x01
	header := &types.Header{InteractionRoot: &tamperedRoot, InteractionCount: &correctCount}

	err := validateAGNT2InteractionFields(header, receipts)
	if err == nil {
		t.Fatalf("expected sequencer-misbehavior reject, got nil")
	}
	if !strings.Contains(err.Error(), "invalid interaction root") {
		t.Fatalf("expected root-mismatch error, got: %v", err)
	}
}

// TestValidateAGNT2InteractionFields_SequencerMisbehavior_WrongCount: a
// header with the right root but wrong count is also invalid — the count
// is part of the consensus commitment.
func TestValidateAGNT2InteractionFields_SequencerMisbehavior_WrongCount(t *testing.T) {
	leaf := mustMakeLeaf("test-wf", "step-1", "role-1", big.NewInt(1000), [32]byte{})
	receipts := []*types.Receipt{{Logs: []*types.Log{makeAgnt2LeafLog(0, leaf)}}}

	correctRoot, correctCount := types.FoldInteractionRoot(receipts)
	wrongCount := correctCount + 1
	header := &types.Header{InteractionRoot: &correctRoot, InteractionCount: &wrongCount}

	err := validateAGNT2InteractionFields(header, receipts)
	if err == nil {
		t.Fatalf("expected count-mismatch reject, got nil")
	}
	if !strings.Contains(err.Error(), "invalid interaction count") {
		t.Fatalf("expected count-mismatch error, got: %v", err)
	}
}

// TestValidateAGNT2InteractionFields_MissingLog: if a sequencer declares
// values that include an extra leaf not present in any receipt log, the
// fold reproduces the wrong root and the validator rejects.
func TestValidateAGNT2InteractionFields_MissingLog(t *testing.T) {
	leaf0 := mustMakeLeaf("wf", "s1", "r1", big.NewInt(1), [32]byte{})
	leaf1 := mustMakeLeaf("wf", "s2", "r2", big.NewInt(2), leaf0)
	withBoth := []*types.Receipt{{Logs: []*types.Log{makeAgnt2LeafLog(0, leaf0), makeAgnt2LeafLog(1, leaf1)}}}
	withOnlyOne := []*types.Receipt{{Logs: []*types.Log{makeAgnt2LeafLog(0, leaf0)}}}

	// Sequencer declares values from "withBoth" but the actual block
	// only contains "withOnlyOne" — reorg, censorship, or sequencer error.
	declaredRoot, declaredCount := types.FoldInteractionRoot(withBoth)
	header := &types.Header{InteractionRoot: &declaredRoot, InteractionCount: &declaredCount}

	if err := validateAGNT2InteractionFields(header, withOnlyOne); err == nil {
		t.Fatalf("expected reject for declared values that don't match actual receipts")
	}
}

// TestValidateAGNT2InteractionFields_EmptyBlock: a post-fork block with
// zero AGNT2 interactions has the empty-MMR root and count 0. Header
// must declare exactly those.
func TestValidateAGNT2InteractionFields_EmptyBlock(t *testing.T) {
	receipts := []*types.Receipt{}
	root, count := types.FoldInteractionRoot(receipts)
	if count != 0 {
		t.Fatalf("empty-block count must be 0, got %d", count)
	}
	header := &types.Header{InteractionRoot: &root, InteractionCount: &count}
	if err := validateAGNT2InteractionFields(header, receipts); err != nil {
		t.Fatalf("empty-block validation failed: %v", err)
	}
}

// --- helpers ---

func makeAgnt2LeafLog(stepIndex uint32, leafHash [32]byte) *types.Log {
	var stepIDHash, agentRoleHash, payout [32]byte
	stepIDHash[0] = 0xbb
	agentRoleHash[0] = 0xcc
	binary.BigEndian.PutUint32(payout[28:32], stepIndex)

	data := types.EncodeAGNT2LeafLogData(stepIndex, stepIDHash, agentRoleHash, payout, leafHash)
	return &types.Log{
		Address: types.AGNT2InteractionPrecompileAddressForTest(),
		Topics:  []common.Hash{types.AGNT2LeafEventTopic0ForTest(), common.Hash{0xaa}},
		Data:    data,
	}
}

func mustMakeLeaf(workflowID, stepID, agentRole string, payout *big.Int, prevLeafHash [32]byte) [32]byte {
	var buf []byte
	buf = append(buf, crypto.Keccak256([]byte(workflowID))...)
	buf = append(buf, crypto.Keccak256([]byte(stepID))...)
	buf = append(buf, crypto.Keccak256([]byte(agentRole))...)
	padded := make([]byte, 32)
	payout.FillBytes(padded)
	buf = append(buf, padded...)
	buf = append(buf, prevLeafHash[:]...)

	var h [32]byte
	copy(h[:], crypto.Keccak256(buf))
	return h
}
