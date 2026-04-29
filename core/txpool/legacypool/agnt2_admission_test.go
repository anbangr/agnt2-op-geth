package legacypool

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

func agnt2InvokeTxData(nonce uint64, gaslimit uint64, gasFee *big.Int, tip *big.Int, modify func(*types.InvokeTx)) *types.InvokeTx {
	txData := &types.InvokeTx{
		ChainID:      params.TestChainConfig.ChainID,
		Nonce:        nonce,
		GasTipCap:    tip,
		GasFeeCap:    gasFee,
		Gas:          gaslimit,
		WorkflowId:   common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		StepId:       1,
		AgentRole:    "worker",
		DepInvokeIds: []common.Hash{},
		Payload:      []byte("payload"),
	}
	if modify != nil {
		modify(txData)
	}
	return txData
}

func agnt2RespondTxData(nonce uint64, gaslimit uint64, gasFee *big.Int, tip *big.Int) *types.RespondTx {
	return &types.RespondTx{
		ChainID:         params.TestChainConfig.ChainID,
		Nonce:           nonce,
		GasTipCap:       tip,
		GasFeeCap:       gasFee,
		Gas:             gaslimit,
		WorkflowId:      common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		StepId:          1,
		InvokeRef:       common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
		ResponsePayload: []byte("response"),
		Status:          0,
	}
}

func agnt2ComposeTxData(nonce uint64, gaslimit uint64, gasFee *big.Int, tip *big.Int) *types.ComposeTypedTx {
	return &types.ComposeTypedTx{
		ChainID:    params.TestChainConfig.ChainID,
		Nonce:      nonce,
		GasTipCap:  tip,
		GasFeeCap:  gasFee,
		Gas:        gaslimit,
		WorkflowId: common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		StepCount:  2,
		StepWorkflowRoots: []common.Hash{
			common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333"),
			common.HexToHash("0x4444444444444444444444444444444444444444444444444444444444444444"),
		},
		Payouts: []*big.Int{big.NewInt(1), big.NewInt(2)},
	}
}

func signTx(t *testing.T, txData types.TxData, key *ecdsa.PrivateKey) *types.Transaction {
	t.Helper()
	tx, err := types.SignNewTx(key, types.LatestSignerForChainID(params.TestChainConfig.ChainID), txData)
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}
	return tx
}

func setupAgnt2AdmissionPool(t *testing.T) (*LegacyPool, *ecdsa.PrivateKey, common.Address) {
	t.Helper()

	pool, key := setupPoolWithConfig(params.TestChainConfig)
	t.Cleanup(func() { pool.Close() })
	addr := crypto.PubkeyToAddress(key.PublicKey)
	testAddBalance(pool, addr, big.NewInt(1000000000000000000))
	return pool, key, addr
}

func TestAgnt2Admission(t *testing.T) {
	t.Run("Valid InvokeTx admitted", func(t *testing.T) {
		pool, key, _ := setupAgnt2AdmissionPool(t)
		txData := agnt2InvokeTxData(0, 100000, big.NewInt(1000000000), big.NewInt(1000000000), nil)
		tx := signTx(t, txData, key)
		err := pool.addRemoteSync(tx)
		if err != nil {
			t.Fatalf("expected admission, got error: %v", err)
		}
	})

	t.Run("Valid RespondTx admitted", func(t *testing.T) {
		pool, key, _ := setupAgnt2AdmissionPool(t)
		tx := signTx(t, agnt2RespondTxData(0, 100000, big.NewInt(1000000000), big.NewInt(1000000000)), key)
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("expected admission, got error: %v", err)
		}
	})

	t.Run("Valid ComposeTypedTx admitted", func(t *testing.T) {
		pool, key, _ := setupAgnt2AdmissionPool(t)
		tx := signTx(t, agnt2ComposeTxData(0, 100000, big.NewInt(1000000000), big.NewInt(1000000000)), key)
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("expected admission, got error: %v", err)
		}
	})

	t.Run("Unknown type byte rejected with ErrTxTypeNotSupported", func(t *testing.T) {
		pool, key, _ := setupAgnt2AdmissionPool(t)
		// Use BlobTx as an unsupported typed transaction for this pool.
		txData := &types.BlobTx{
			ChainID:    uint256.MustFromBig(params.TestChainConfig.ChainID),
			Nonce:      1,
			GasTipCap:  uint256.NewInt(1000000000),
			GasFeeCap:  uint256.NewInt(1000000000),
			Gas:        100000,
			To:         common.Address{1},
			Value:      uint256.NewInt(0),
			Data:       nil,
			BlobFeeCap: uint256.NewInt(1000000000),
			BlobHashes: []common.Hash{},
		}
		tx := signTx(t, txData, key)
		err := pool.addRemoteSync(tx)
		if !errors.Is(err, core.ErrTxTypeNotSupported) {
			t.Fatalf("expected core.ErrTxTypeNotSupported, got: %v", err)
		}
	})

	t.Run("Signature recovers to non-zero address", func(t *testing.T) {
		pool, key, _ := setupAgnt2AdmissionPool(t)
		txData := agnt2InvokeTxData(2, 100000, big.NewInt(1000000000), big.NewInt(1000000000), nil)
		tx := signTx(t, txData, key)
		from, err := types.Sender(pool.signer, tx)
		if err != nil {
			t.Fatalf("expected sender recovery, got: %v", err)
		}
		if from == (common.Address{}) {
			t.Fatalf("expected non-zero recovered sender")
		}
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("expected admission after sender recovery, got: %v", err)
		}
	})

	t.Run("AgentRole > 64 bytes rejected", func(t *testing.T) {
		pool, key, _ := setupAgnt2AdmissionPool(t)
		txData := agnt2InvokeTxData(3, 100000, big.NewInt(1000000000), big.NewInt(1000000000), func(tx *types.InvokeTx) {
			tx.AgentRole = strings.Repeat("A", 65)
		})
		tx := signTx(t, txData, key)
		err := pool.addRemoteSync(tx)
		if !errors.Is(err, types.ErrAgnt2AgentRoleTooLong) {
			t.Fatalf("expected ErrAgnt2AgentRoleTooLong, got: %v", err)
		}
	})

	t.Run("Payload > 16 KiB rejected", func(t *testing.T) {
		pool, key, _ := setupAgnt2AdmissionPool(t)
		txData := agnt2InvokeTxData(4, 100000, big.NewInt(1000000000), big.NewInt(1000000000), func(tx *types.InvokeTx) {
			tx.Payload = make([]byte, 16*1024+1)
		})
		tx := signTx(t, txData, key)
		err := pool.addRemoteSync(tx)
		if !errors.Is(err, types.ErrAgnt2PayloadTooLarge) {
			t.Fatalf("expected ErrAgnt2PayloadTooLarge, got: %v", err)
		}
	})

	t.Run("DepInvokeIds nil rejected", func(t *testing.T) {
		pool, key, _ := setupAgnt2AdmissionPool(t)
		txData := agnt2InvokeTxData(5, 100000, big.NewInt(1000000000), big.NewInt(1000000000), func(tx *types.InvokeTx) {
			tx.DepInvokeIds = nil
		})
		tx := signTx(t, txData, key)
		err := pool.addRemoteSync(tx)
		if !errors.Is(err, types.ErrAgnt2DepInvokeIdsNil) {
			t.Fatalf("expected ErrAgnt2DepInvokeIdsNil, got: %v", err)
		}
	})

	t.Run("Stale nonce rejected", func(t *testing.T) {
		pool, key, addr := setupAgnt2AdmissionPool(t)
		testSetNonce(pool, addr, 10)
		txDataStale := agnt2InvokeTxData(5, 100000, big.NewInt(1000000000), big.NewInt(1000000000), nil)
		txStale := signTx(t, txDataStale, key)
		errStale := pool.addRemoteSync(txStale)
		if !errors.Is(errStale, core.ErrNonceTooLow) {
			t.Fatalf("expected ErrNonceTooLow, got: %v", errStale)
		}
	})

	t.Run("Gas fee caps within network bounds", func(t *testing.T) {
		pool, key, _ := setupAgnt2AdmissionPool(t)
		// Fee cap is 0, which is below the minimum required by network/pool
		txData := agnt2InvokeTxData(10, 100000, big.NewInt(0), big.NewInt(0), nil)
		tx := signTx(t, txData, key)
		err := pool.addRemoteSync(tx)
		if !errors.Is(err, txpool.ErrTxGasPriceTooLow) && !errors.Is(err, txpool.ErrUnderpriced) && !errors.Is(err, core.ErrFeeCapTooLow) {
			t.Fatalf("expected underpriced or fee cap too low error, got: %v", err)
		}
	})
}
