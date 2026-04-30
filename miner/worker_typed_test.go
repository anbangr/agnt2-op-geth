package miner

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/internal/agnt2debug"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/stretchr/testify/require"
)

func newTestInvokeTx(workflowId common.Hash, stepId uint8, deps []common.Hash) *types.Transaction {
	key, _ := crypto.GenerateKey()
	return newTestInvokeTxWithKeyNonce(key, workflowId, stepId, 1, deps)
}

func newTestInvokeTxWithKeyNonce(key *ecdsa.PrivateKey, workflowId common.Hash, stepId uint8, nonce uint64, deps []common.Hash) *types.Transaction {
	tx := &types.InvokeTx{
		ChainID:      big.NewInt(9001),
		Nonce:        nonce,
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

func newTestComposeTypedTx(workflowId common.Hash, stepCount uint8) *types.Transaction {
	key, _ := crypto.GenerateKey()
	tx := &types.ComposeTypedTx{
		ChainID:    big.NewInt(9001),
		Nonce:      1,
		GasTipCap:  big.NewInt(1_000_000_000),
		GasFeeCap:  big.NewInt(20_000_000_000),
		Gas:        100000,
		WorkflowId: workflowId,
		StepCount:  stepCount,
		StepWorkflowRoots: []common.Hash{
			common.HexToHash("0x0100000000000000000000000000000000000000000000000000000000000000"),
			common.HexToHash("0x0200000000000000000000000000000000000000000000000000000000000000"),
		}[:stepCount],
		Payouts: []*big.Int{big.NewInt(1), big.NewInt(2)}[:stepCount],
	}
	signedTx, _ := types.SignNewTx(key, types.LatestSignerForChainID(big.NewInt(9001)), tx)
	return signedTx
}

func setupTypedEnv(t *testing.T) (*Miner, *environment) {
	miner := createMiner(t)
	st, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	env := &environment{
		signer:   types.LatestSignerForChainID(big.NewInt(9001)),
		state:    st,
		header:   &types.Header{Number: big.NewInt(1)},
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

// TestCommitTypedTransactions_MixedTypedOrder verifies a scrambled mixed batch admits
// InvokeTx, RespondTx, and ComposeTypedTx while preserving the Invoke -> Respond edge.
func TestCommitTypedTransactions_MixedTypedOrder(t *testing.T) {
	miner, env := setupTypedEnv(t)
	ctx := context.Background()

	wfId := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000011")
	invokeTx := newTestInvokeTx(wfId, 1, []common.Hash{})
	respondTx := newTestRespondTx(wfId, 2, invokeTx.Hash())
	composeTx := newTestComposeTypedTx(wfId, 2)

	err := miner.commitTypedTransactions(ctx, env, []*types.Transaction{respondTx, composeTx, invokeTx})
	require.NoError(t, err)

	require.Len(t, env.txs, 3)
	positions := make(map[common.Hash]int)
	for i, tx := range env.txs {
		positions[tx.Hash()] = i
	}
	require.Less(t, positions[invokeTx.Hash()], positions[respondTx.Hash()], "RespondTx must follow its InvokeTx")
	require.Contains(t, positions, composeTx.Hash(), "ComposeTypedTx is independent in E4.3 and must still be admitted")
}

// TestCommitTypedTransactions_CycleDetection verifies the graph cycle path. Real
// tx-hash cycles are cryptographic fixed points, so the dependency hook injects
// the graph shape while still exercising commitTypedTransactions counters/output.
func TestCommitTypedTransactions_CycleDetection(t *testing.T) {
	miner, env := setupTypedEnv(t)
	ctx := context.Background()

	wfId := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000012")
	tx1 := newTestInvokeTx(wfId, 1, []common.Hash{})
	tx2 := newTestInvokeTx(wfId, 2, []common.Hash{})

	oldDeps := agnt2TypedTxDependencies
	agnt2TypedTxDependencies = func(tx *types.Transaction) []common.Hash {
		switch tx.Hash() {
		case tx1.Hash():
			return []common.Hash{tx2.Hash()}
		case tx2.Hash():
			return []common.Hash{tx1.Hash()}
		default:
			return oldDeps(tx)
		}
	}
	defer func() { agnt2TypedTxDependencies = oldDeps }()

	counter := metrics.GetOrRegisterCounter("miner/typedTx/cycle", nil)
	counter.Clear()

	err := miner.commitTypedTransactions(ctx, env, []*types.Transaction{tx1, tx2})
	require.NoError(t, err)

	require.Len(t, env.txs, 0, "cycle members must not be admitted")
	require.EqualValues(t, 2, metrics.GetOrRegisterCounter("miner/typedTx/cycle", nil).Load())
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

// TestCommitTypedTransactions_DuplicateLogicalOpIdDeduped verifies that two distinct
// signed txs with the same typed operation id admit only the first one.
func TestCommitTypedTransactions_DuplicateLogicalOpIdDeduped(t *testing.T) {
	miner, env := setupTypedEnv(t)
	ctx := context.Background()

	wfId := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000013")
	key1, _ := crypto.GenerateKey()
	key2, _ := crypto.GenerateKey()
	tx1 := newTestInvokeTxWithKeyNonce(key1, wfId, 1, 1, []common.Hash{})
	tx2 := newTestInvokeTxWithKeyNonce(key2, wfId, 1, 2, []common.Hash{})
	require.NotEqual(t, tx1.Hash(), tx2.Hash(), "test must use distinct signed transactions")

	counter := metrics.GetOrRegisterCounter("miner/typedTx/duplicateOpId", nil)
	counter.Clear()

	err := miner.commitTypedTransactions(ctx, env, []*types.Transaction{tx1, tx2})
	require.NoError(t, err)

	require.Len(t, env.txs, 1, "duplicate logical op id must admit only one tx")
	require.Equal(t, tx1.Hash(), env.txs[0].Hash())
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

// TestCommitTypedTransactions_StaleNonce verifies that a typed tx below the
// sender's state nonce is rejected and increments staleNonce.
func TestCommitTypedTransactions_StaleNonce(t *testing.T) {
	miner, env := setupTypedEnv(t)
	ctx := context.Background()

	wfId := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000006")
	key, _ := crypto.GenerateKey()
	tx1 := newTestInvokeTxWithKeyNonce(key, wfId, 1, 1, []common.Hash{})
	sender, err := types.Sender(env.signer, tx1)
	require.NoError(t, err)
	env.state.SetNonce(sender, tx1.Nonce()+1, tracing.NonceChangeUnspecified)

	counter := metrics.GetOrRegisterCounter("miner/typedTx/staleNonce", nil)
	counter.Clear()

	err = miner.commitTypedTransactions(ctx, env, []*types.Transaction{tx1})
	require.NoError(t, err)

	require.Len(t, env.txs, 0, "stale nonce tx must not be admitted")
	require.EqualValues(t, 1, metrics.GetOrRegisterCounter("miner/typedTx/staleNonce", nil).Load())
}

// TestCommitTypedTransactions_BadOrderSwap verifies the E4.6 bad-order injection path:
// when agnt2debug.SetBadOrder is called for a block, commitTypedTransactions swaps
// the two entries at the given indices in the topologically-sorted output.
func TestCommitTypedTransactions_BadOrderSwap(t *testing.T) {
	miner, env := setupTypedEnv(t)
	ctx := context.Background()

	// Use block 9999 so this test cannot interfere with other tests.
	blockNum := uint64(9999)
	env.header.Number = big.NewInt(int64(blockNum))

	wfId := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000007")
	tx1 := newTestInvokeTx(wfId, 1, []common.Hash{})
	tx2 := newTestInvokeTx(wfId, 2, []common.Hash{tx1.Hash()})

	// Without injection, topological order places tx1 before tx2.
	err := miner.commitTypedTransactions(ctx, env, []*types.Transaction{tx2, tx1})
	require.NoError(t, err)
	require.Len(t, env.txs, 2)
	naturalFirst := env.txs[0].Hash()
	naturalSecond := env.txs[1].Hash()
	require.Equal(t, tx1.Hash(), naturalFirst, "tx1 (no deps) must be first in natural order")

	// Reset env and inject bad order for the same block — indices [0,1] swap positions 0 and 1.
	env.txs = env.txs[:0]
	agnt2debug.SetBadOrder(blockNum, []int{0, 1})

	err = miner.commitTypedTransactions(ctx, env, []*types.Transaction{tx2, tx1})
	require.NoError(t, err)
	require.Len(t, env.txs, 2)

	// After swap, the order must be inverted relative to natural topological order.
	require.Equal(t, naturalSecond, env.txs[0].Hash(), "swap must move position-1 to position-0")
	require.Equal(t, naturalFirst, env.txs[1].Hash(), "swap must move position-0 to position-1")

	// Consume-once: a second run without re-injection must restore natural order.
	env.txs = env.txs[:0]
	err = miner.commitTypedTransactions(ctx, env, []*types.Transaction{tx2, tx1})
	require.NoError(t, err)
	require.Equal(t, naturalFirst, env.txs[0].Hash(), "no injection on second run — natural order restored")
}
