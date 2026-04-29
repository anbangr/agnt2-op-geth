package agnt2typedtx

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	InvokeTxType       = 0x7a
	RespondTxType      = 0x7b
	ComposeTypedTxType = 0x7c
)

type InvokeTxData struct {
	ChainID      *big.Int
	Nonce        uint64
	GasTipCap    *big.Int
	GasFeeCap    *big.Int
	Gas          uint64
	WorkflowId   common.Hash
	StepId       uint64
	AgentRole    string
	DepInvokeIds []common.Hash
	Payload      []byte
	V            *big.Int
	R            *big.Int
	S            *big.Int
}

type RespondTxData struct {
	ChainID         *big.Int
	Nonce           uint64
	GasTipCap       *big.Int
	GasFeeCap       *big.Int
	Gas             uint64
	WorkflowId      common.Hash
	StepId          uint64
	InvokeRef       common.Hash
	ResponsePayload []byte
	Status          uint64
	V               *big.Int
	R               *big.Int
	S               *big.Int
}

type ComposeTypedTxData struct {
	ChainID           *big.Int
	Nonce             uint64
	GasTipCap         *big.Int
	GasFeeCap         *big.Int
	Gas               uint64
	WorkflowId        common.Hash
	StepCount         uint64
	StepWorkflowRoots []common.Hash
	Payouts           []*big.Int
	V                 *big.Int
	R                 *big.Int
	S                 *big.Int
}

func EncodeInvokeTxRLP(tx *InvokeTxData) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.WriteByte(InvokeTxType)
	err := rlp.Encode(buf, []interface{}{
		tx.ChainID, tx.Nonce, tx.GasTipCap, tx.GasFeeCap, tx.Gas, tx.WorkflowId, tx.StepId, []byte(tx.AgentRole), tx.DepInvokeIds, tx.Payload, tx.V, tx.R, tx.S,
	})
	return buf.Bytes(), err
}

func EncodeRespondTxRLP(tx *RespondTxData) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.WriteByte(RespondTxType)
	err := rlp.Encode(buf, []interface{}{
		tx.ChainID, tx.Nonce, tx.GasTipCap, tx.GasFeeCap, tx.Gas, tx.WorkflowId, tx.StepId, tx.InvokeRef, tx.ResponsePayload, tx.Status, tx.V, tx.R, tx.S,
	})
	return buf.Bytes(), err
}

func EncodeComposeTypedTxRLP(tx *ComposeTypedTxData) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.WriteByte(ComposeTypedTxType)
	err := rlp.Encode(buf, []interface{}{
		tx.ChainID, tx.Nonce, tx.GasTipCap, tx.GasFeeCap, tx.Gas, tx.WorkflowId, tx.StepCount, tx.StepWorkflowRoots, tx.Payouts, tx.V, tx.R, tx.S,
	})
	return buf.Bytes(), err
}

func SighashInvoke(tx *InvokeTxData) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(InvokeTxType)
	rlp.Encode(buf, []interface{}{
		tx.ChainID, tx.Nonce, tx.GasTipCap, tx.GasFeeCap, tx.Gas, tx.WorkflowId, tx.StepId, []byte(tx.AgentRole), tx.DepInvokeIds, tx.Payload,
	})
	return crypto.Keccak256(buf.Bytes())
}

func SighashRespond(tx *RespondTxData) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(RespondTxType)
	rlp.Encode(buf, []interface{}{
		tx.ChainID, tx.Nonce, tx.GasTipCap, tx.GasFeeCap, tx.Gas, tx.WorkflowId, tx.StepId, tx.InvokeRef, tx.ResponsePayload, tx.Status,
	})
	return crypto.Keccak256(buf.Bytes())
}

func SighashComposeTyped(tx *ComposeTypedTxData) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(ComposeTypedTxType)
	rlp.Encode(buf, []interface{}{
		tx.ChainID, tx.Nonce, tx.GasTipCap, tx.GasFeeCap, tx.Gas, tx.WorkflowId, tx.StepCount, tx.StepWorkflowRoots, tx.Payouts,
	})
	return crypto.Keccak256(buf.Bytes())
}
