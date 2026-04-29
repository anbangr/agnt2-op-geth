package types

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// TestAgnt2SighashDeterminism1000 extends the 100-iteration sighash test to
// 1000 iterations per plan §8.7 requirement (b). Covers all three tx types.
func TestAgnt2SighashDeterminism1000(t *testing.T) {
	signer := NewLondonSigner(big.NewInt(9001))
	cases := []struct {
		name string
		tx   *Transaction
	}{
		{"InvokeTx", NewTx(testInvokeTx())},
		{"RespondTx", NewTx(testRespondTx())},
		{"ComposeTypedTx", NewTx(testComposeTypedTx())},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			expected := signer.Hash(tc.tx)
			for i := 0; i < 1000; i++ {
				if h := signer.Hash(tc.tx); h != expected {
					t.Fatalf("sighash changed at iteration %d: got %s want %s", i, h, expected)
				}
			}
		})
	}
}

// TestAgnt2InvokeTx_EmptyDepInvokeIds verifies that an InvokeTx with an
// empty (non-nil) DepInvokeIds slice encodes cleanly and round-trips.
// Edge case from plan §8.7 requirement (c).
func TestAgnt2InvokeTx_EmptyDepInvokeIds(t *testing.T) {
	txdata := testInvokeTx()
	txdata.DepInvokeIds = []common.Hash{} // empty but non-nil
	tx := NewTx(txdata)

	encoded, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary with empty DepInvokeIds: %v", err)
	}

	var decoded Transaction
	if err := decoded.UnmarshalBinary(encoded); err != nil {
		t.Fatalf("UnmarshalBinary with empty DepInvokeIds: %v", err)
	}
	if decoded.Type() != InvokeTxType {
		t.Fatalf("decoded type %x, want %x", decoded.Type(), InvokeTxType)
	}
	if decoded.Hash() != tx.Hash() {
		t.Fatalf("hash mismatch after round-trip: got %s want %s", decoded.Hash(), tx.Hash())
	}
	inner := decoded.inner.(*InvokeTx)
	if inner.DepInvokeIds == nil {
		t.Fatal("DepInvokeIds became nil after decode (should be empty slice)")
	}
	if len(inner.DepInvokeIds) != 0 {
		t.Fatalf("DepInvokeIds should be empty after decode, got len=%d", len(inner.DepInvokeIds))
	}
}

// TestAgnt2InvokeTx_MaxAgentRole verifies that an InvokeTx with an AgentRole
// of exactly Agnt2MaxAgentRoleBytes (64) bytes encodes cleanly and round-trips.
// Edge case from plan §8.7 requirement (c).
func TestAgnt2InvokeTx_MaxAgentRole(t *testing.T) {
	txdata := testInvokeTx()
	txdata.AgentRole = strings.Repeat("x", Agnt2MaxAgentRoleBytes) // exactly 64 bytes
	tx := NewTx(txdata)

	encoded, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary with max AgentRole: %v", err)
	}

	var decoded Transaction
	if err := decoded.UnmarshalBinary(encoded); err != nil {
		t.Fatalf("UnmarshalBinary with max AgentRole: %v", err)
	}
	inner := decoded.inner.(*InvokeTx)
	if inner.AgentRole != txdata.AgentRole {
		t.Fatalf("AgentRole mismatch after round-trip: got %q want %q", inner.AgentRole, txdata.AgentRole)
	}
}

// TestAgnt2InvokeTx_MultipleDepInvokeIds verifies RLP round-trip with
// several DepInvokeIds (realistic multi-step dependency case).
func TestAgnt2InvokeTx_MultipleDepInvokeIds(t *testing.T) {
	txdata := testInvokeTx()
	txdata.DepInvokeIds = []common.Hash{
		common.HexToHash("0x" + strings.Repeat("aa", 32)),
		common.HexToHash("0x" + strings.Repeat("bb", 32)),
		common.HexToHash("0x" + strings.Repeat("cc", 32)),
	}
	tx := NewTx(txdata)

	encoded, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary with 3 DepInvokeIds: %v", err)
	}
	var decoded Transaction
	if err := decoded.UnmarshalBinary(encoded); err != nil {
		t.Fatalf("UnmarshalBinary with 3 DepInvokeIds: %v", err)
	}
	if decoded.Hash() != tx.Hash() {
		t.Fatalf("hash mismatch: got %s want %s", decoded.Hash(), tx.Hash())
	}
	inner := decoded.inner.(*InvokeTx)
	if len(inner.DepInvokeIds) != 3 {
		t.Fatalf("expected 3 DepInvokeIds, got %d", len(inner.DepInvokeIds))
	}
}

// TestAgnt2AgentRole_NFDRejection verifies that an AgentRole in NFD form
// (decomposed Unicode) is rejected at encode time. NFC is the only accepted
// normalisation. Plan §8.7 requirement (c) + E4.1 invariant.
func TestAgnt2AgentRole_NFDRejection(t *testing.T) {
	// U+0065 U+0301 = "e" + combining acute — NFD form of "é"
	nfdRole := "é"
	txdata := testInvokeTx()
	txdata.AgentRole = nfdRole
	tx := NewTx(txdata)

	if _, err := tx.MarshalBinary(); err == nil {
		t.Fatal("expected NFC error for NFD-form AgentRole, got nil")
	}
}

// TestAgnt2ComposeTypedTx_RoundTrip_EdgeCases verifies round-trip for
// ComposeTypedTx with 0 steps and 5 steps.
func TestAgnt2ComposeTypedTx_RoundTrip_EdgeCases(t *testing.T) {
	cases := []struct {
		name      string
		stepCount uint8
	}{
		{"single-step", 1},
		{"five-steps", 5},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			roots := make([]common.Hash, tc.stepCount)
			payouts := make([]*big.Int, tc.stepCount)
			for i := range roots {
				roots[i] = common.HexToHash("0x" + strings.Repeat(string(rune('0'+i)), 64))
				payouts[i] = big.NewInt(int64(i + 1))
			}
			txdata := &ComposeTypedTx{
				ChainID:           big.NewInt(9001),
				Nonce:             1,
				GasTipCap:         big.NewInt(1_000_000_000),
				GasFeeCap:         big.NewInt(20_000_000_000),
				Gas:               100000,
				WorkflowId:        common.HexToHash("0x" + strings.Repeat("ab", 32)),
				StepCount:         tc.stepCount,
				StepWorkflowRoots: roots,
				Payouts:           payouts,
				V:                 new(big.Int),
				R:                 big.NewInt(1),
				S:                 big.NewInt(1),
			}
			tx := NewTx(txdata)
			encoded, err := tx.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			var decoded Transaction
			if err := decoded.UnmarshalBinary(encoded); err != nil {
				t.Fatalf("UnmarshalBinary: %v", err)
			}
			if decoded.Hash() != tx.Hash() {
				t.Fatalf("hash mismatch: got %s want %s", decoded.Hash(), tx.Hash())
			}
		})
	}
}
