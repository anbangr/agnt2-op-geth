package core

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

// TestValidateAGNT2TypedReexecFields exercises the B2' Stage 2 round-trip: a
// header committing the canonical FoldTypedReexecRoot value validates; a tampered
// root or a half-pair (one nil) is rejected.
func TestValidateAGNT2TypedReexecFields(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	signer := types.LatestSignerForChainID(big.NewInt(9001))
	tx, err := types.SignNewTx(key, signer, &types.InvokeTx{
		ChainID: big.NewInt(9001), Nonce: 0, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
		Gas: 100000, WorkflowId: common.HexToHash("0x77"), StepId: 1, AgentRole: "worker",
		DepInvokeIds: []common.Hash{}, Payload: []byte("call-data"),
	})
	require.NoError(t, err)
	txs := []*types.Transaction{tx}

	root, count := types.FoldTypedReexecRoot(txs, signer)
	require.EqualValues(t, 1, count)

	// Correct commitment validates.
	good := &types.Header{TypedReexecRoot: &root, TypedReexecCount: &count}
	require.NoError(t, validateAGNT2TypedReexecFields(good, txs, signer))

	// Absent pair is a clean no-op ONLY when the block has no foldable ops.
	require.NoError(t, validateAGNT2TypedReexecFields(&types.Header{}, []*types.Transaction{}, signer))

	// Omission escape closed (M4): an absent pair with foldable ops is rejected —
	// a producer cannot omit the fraud commitment for a block that has typed ops.
	require.Error(t, validateAGNT2TypedReexecFields(&types.Header{}, txs, signer))

	// Tampered root is rejected.
	bad := root
	bad[0] ^= 0xFF
	require.Error(t, validateAGNT2TypedReexecFields(&types.Header{TypedReexecRoot: &bad, TypedReexecCount: &count}, txs, signer))

	// Half-pair (root set, count nil) is rejected.
	require.Error(t, validateAGNT2TypedReexecFields(&types.Header{TypedReexecRoot: &root}, txs, signer))

	// Wrong count is rejected.
	wrongCount := uint64(2)
	require.Error(t, validateAGNT2TypedReexecFields(&types.Header{TypedReexecRoot: &root, TypedReexecCount: &wrongCount}, txs, signer))
}
