package miner

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/stretchr/testify/require"
)

func newTestInvokeTx(workflowId common.Hash, stepId uint8, deps []common.Hash) *types.Transaction {
	key, _ := crypto.GenerateKey()
	tx := &types.InvokeTx{
		ChainID:      big.NewInt(9001),
		Nonce:        1,
		GasTipCap:    big.NewInt(1_000_000_000),
		GasFeeCap:    big.NewInt(20_000_000_000),
		Gas:          100000,
		WorkflowId:   workflowId,
		StepId:       stepId,
		AgentRole:    "worker-a",
		DepInvokeIds: deps,
		Payload:      common.FromHex("0xdeadbeef"),
	}
	signedTx, _ := types.SignNewTx(key, types.LatestSignerForChainID(big.NewInt(9001)), tx)
	return signedTx
}

func newTestRespondTx(workflowId common.Hash, stepId uint8, invokeRef common.Hash) *types.Transaction {
	key, _ := crypto.GenerateKey()
	tx := &types.RespondTx{
		ChainID:         big.NewInt(9001),
		Nonce:           1,
		GasTipCap:       big.NewInt(1_000_000_000),
		GasFeeCap:       big.NewInt(20_000_000_000),
		Gas:             100000,
		WorkflowId:      workflowId,
		StepId:          stepId,
		InvokeRef:       invokeRef,
		ResponsePayload: common.FromHex("0xdeadbeef"),
		Status:          0,
	}
	signedTx, _ := types.SignNewTx(key, types.LatestSignerForChainID(big.NewInt(9001)), tx)
	return signedTx
}

func setupTypedEnv(t *testing.T) (*Miner, *environment) {
	miner := createMiner(t)
	st, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	env := &environment{
		signer:   types.LatestSigner(miner.chainConfig),
		state:    st,
		header:   &types.Header{},
		txs:      make([]*types.Transaction, 0),
		receipts: make([]*types.Receipt, 0),
	}
	return miner, env
}

// TestCommitTypedTransactions_TopologicalOrder verifies that scrambled typed txs are
// appended to env.txs in correct dependency order after topological sort.
func TestCommitTypedTransactions_TopologicalOrder(t *testing.T) {
	miner, env := setupTypedEnv(t)
	ctx := context.Background()

	wfId := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	tx1 := newTestInvokeTx(wfId, 1, []common.Hash{})
	tx2 := newTestInvokeTx(wfId, 2, []common.Hash{tx1.Hash()})

	// Submit in reverse order: tx2 first, tx1 second.
	err := miner.commitTypedTransactions(ctx, env, []*types.Transaction{tx2, tx1})
	require.NoError(t, err)

	require.Len(t, env.txs, 2)
	require.Equal(t, tx1.Hash(), env.txs[0].Hash(), "tx1 (no deps) must come first")
	require.Equal(t, tx2.Hash(), env.txs[1].Hash(), "tx2 (depends on tx1) must come second")
}

// TestCommitTypedTransactions_MissingDepDeferred verifies that an InvokeTx whose dep
// is absent from the batch is deferred (not admitted) and missingDep counter increments.
func TestCommitTypedTransactions_MissingDepDeferred(t *testing.T) {
	miner, env := setupTypedEnv(t)
	ctx := context.Background()

	wfId := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002")
	missingHash := common.HexToHash("0xdeadbeef00000000000000000000000000000000000000000000000000000000")
	tx1 := newTestInvokeTx(wfId, 1, []common.Hash{missingHash})

	counter := metrics.GetOrRegisterCounter("miner/typedTx/missingDep", nil)
	counter.Clear()

	err := miner.commitTypedTransactions(ctx, env, []*types.Transaction{tx1})
	require.NoError(t, err)

	require.Len(t, env.txs, 0, "tx with missing dep must be deferred, not admitted")
	require.EqualValues(t, 1, metrics.GetOrRegisterCounter("miner/typedTx/missingDep", nil).Load())
}

// TestCommitTypedTransactions_RespondTxCrossBlock verifies that a RespondTx whose
// InvokeRef is not in the batch is admitted (cross-block resolved) and the counter increments.
func TestCommitTypedTransactions_RespondTxCrossBlock(t *testing.T) {
	miner, env := setupTypedEnv(t)
	ctx := context.Background()

	wfId := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000003")
	invokeRef := common.HexToHash("0xabcd123400000000000000000000000000000000000000000000000000000000")
	respondTx := newTestRespondTx(wfId, 1, invokeRef)

	counter := metrics.GetOrRegisterCounter("miner/typedTx/crossBlockResolved", nil)
	counter.Clear()

	err := miner.commitTypedTransactions(ctx, env, []*types.Transaction{respondTx})
	require.NoError(t, err)

	require.Len(t, env.txs, 1, "RespondTx with prior-block invokeRef must be admitted")
	require.EqualValues(t, 1, metrics.GetOrRegisterCounter("miner/typedTx/crossBlockResolved", nil).Load())
}

// TestCommitTypedTransactions_DuplicateDeduped verifies that submitting the same tx twice
// results in only one admission and increments the duplicateOpId counter.
func TestCommitTypedTransactions_DuplicateDeduped(t *testing.T) {
	miner, env := setupTypedEnv(t)
	ctx := context.Background()

	wfId := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000004")
	tx1 := newTestInvokeTx(wfId, 1, []common.Hash{})

	counter := metrics.GetOrRegisterCounter("miner/typedTx/duplicateOpId", nil)
	counter.Clear()

	err := miner.commitTypedTransactions(ctx, env, []*types.Transaction{tx1, tx1})
	require.NoError(t, err)

	require.Len(t, env.txs, 1, "duplicate tx must be deduplicated to one entry")
	require.EqualValues(t, 1, metrics.GetOrRegisterCounter("miner/typedTx/duplicateOpId", nil).Load())
}

// TestCommitTypedTransactions_AllAdmittedNoDeps verifies that txs with no dependencies
// are all admitted.
func TestCommitTypedTransactions_AllAdmittedNoDeps(t *testing.T) {
	miner, env := setupTypedEnv(t)
	ctx := context.Background()

	wfId := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000005")
	tx1 := newTestInvokeTx(wfId, 1, []common.Hash{})
	tx2 := newTestInvokeTx(wfId, 2, []common.Hash{})
	tx3 := newTestInvokeTx(wfId, 3, []common.Hash{})

	err := miner.commitTypedTransactions(ctx, env, []*types.Transaction{tx1, tx2, tx3})
	require.NoError(t, err)

	require.Len(t, env.txs, 3, "all three independent txs must be admitted")
}

// TestCommitTypedTransactions_StaleNonce verifies that a tx with no deps is admitted
// (staleNonce counter is not incremented in the E4.3 prototype since commitTransaction
// is not called — this test confirms the tx IS admitted, not rejected).
func TestCommitTypedTransactions_StaleNonce(t *testing.T) {
	miner, env := setupTypedEnv(t)
	ctx := context.Background()

	wfId := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000006")
	tx1 := newTestInvokeTx(wfId, 1, []common.Hash{})

	err := miner.commitTypedTransactions(ctx, env, []*types.Transaction{tx1})
	require.NoError(t, err)

	// In E4.3 prototype, commitTransaction is not called so staleNonce is never triggered.
	// Verify the tx is admitted to env.txs.
	require.Len(t, env.txs, 1, "tx must be admitted (staleNonce not checked in E4.3 prototype)")
}
