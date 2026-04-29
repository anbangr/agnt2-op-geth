package core

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func newTestTypedTx(t *testing.T, txType byte) *types.Transaction {
	t.Helper()
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	var inner types.TxData
	switch txType {
	case types.InvokeTxType:
		inner = &types.InvokeTx{
			ChainID:   big.NewInt(9001),
			Nonce:     1,
			GasTipCap: big.NewInt(1_000_000_000),
			GasFeeCap: big.NewInt(20_000_000_000),
			Gas:       100000,
			WorkflowId: common.HexToHash("0x01"),
			StepId:    1,
			AgentRole: "worker",
			Payload:   common.FromHex("0xdeadbeef"),
		}
	case types.RespondTxType:
		inner = &types.RespondTx{
			ChainID:         big.NewInt(9001),
			Nonce:           1,
			GasTipCap:       big.NewInt(1_000_000_000),
			GasFeeCap:       big.NewInt(20_000_000_000),
			Gas:             100000,
			WorkflowId:      common.HexToHash("0x01"),
			StepId:          1,
			InvokeRef:       common.HexToHash("0xab"),
			ResponsePayload: common.FromHex("0xdeadbeef"),
		}
	default:
		t.Fatalf("unsupported typed tx type 0x%02x", txType)
	}
	tx, err := types.SignNewTx(key, types.LatestSignerForChainID(big.NewInt(9001)), inner)
	require.NoError(t, err)
	return tx
}

// TestValidateAGNT2TypedOpFields_BothAbsent verifies that a header with no
// TypedOpRoot/TypedOpCount fields (nil/nil) passes validation regardless of
// whether typed txs are present.
func TestValidateAGNT2TypedOpFields_BothAbsent(t *testing.T) {
	header := &types.Header{}
	err := validateAGNT2TypedOpFields(header, nil)
	require.NoError(t, err)
}

// TestValidateAGNT2TypedOpFields_HalfPairRootOnly verifies that a header with
// TypedOpRoot set but TypedOpCount nil is rejected.
func TestValidateAGNT2TypedOpFields_HalfPairRootOnly(t *testing.T) {
	h := common.HexToHash("0xdeadbeef")
	header := &types.Header{TypedOpRoot: &h}
	err := validateAGNT2TypedOpFields(header, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "both be present or both absent")
}

// TestValidateAGNT2TypedOpFields_HalfPairCountOnly verifies that a header with
// TypedOpCount set but TypedOpRoot nil is rejected.
func TestValidateAGNT2TypedOpFields_HalfPairCountOnly(t *testing.T) {
	c := uint64(1)
	header := &types.Header{TypedOpCount: &c}
	err := validateAGNT2TypedOpFields(header, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "both be present or both absent")
}

// TestValidateAGNT2TypedOpFields_CorrectRoot verifies that a header with a
// correctly computed TypedOpRoot and TypedOpCount passes validation.
func TestValidateAGNT2TypedOpFields_CorrectRoot(t *testing.T) {
	tx := newTestTypedTx(t, types.InvokeTxType)
	txs := []*types.Transaction{tx}

	gotRoot, gotCount := types.FoldTypedOpRoot(txs)
	header := &types.Header{TypedOpRoot: &gotRoot, TypedOpCount: &gotCount}

	err := validateAGNT2TypedOpFields(header, txs)
	require.NoError(t, err)
}

// TestValidateAGNT2TypedOpFields_BadRoot verifies that a header with a wrong
// TypedOpRoot is rejected.
func TestValidateAGNT2TypedOpFields_BadRoot(t *testing.T) {
	tx := newTestTypedTx(t, types.RespondTxType)
	txs := []*types.Transaction{tx}

	_, gotCount := types.FoldTypedOpRoot(txs)
	badRoot := common.HexToHash("0xbaaaaaad")
	header := &types.Header{TypedOpRoot: &badRoot, TypedOpCount: &gotCount}

	err := validateAGNT2TypedOpFields(header, txs)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid typed-op root")
}

// TestValidateAGNT2TypedOpFields_InteractionOnlyCompatibility verifies that a
// block with only InteractionRoot set (no TypedOpRoot/TypedOpCount) is valid —
// compatibility blocks must not be rejected by the typed-op validator.
func TestValidateAGNT2TypedOpFields_InteractionOnlyCompatibility(t *testing.T) {
	interRoot := common.HexToHash("0xaabbcc")
	interCount := uint64(3)
	header := &types.Header{
		InteractionRoot:  &interRoot,
		InteractionCount: &interCount,
		// TypedOpRoot and TypedOpCount intentionally absent.
	}
	err := validateAGNT2TypedOpFields(header, nil)
	require.NoError(t, err)
}
