// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// RespondTx is the AGNT2 0x7B typed transaction.
type RespondTx struct {
	ChainID         *big.Int
	Nonce           uint64
	GasTipCap       *big.Int
	GasFeeCap       *big.Int
	Gas             uint64
	WorkflowId      common.Hash
	StepId          uint8
	InvokeRef       common.Hash
	ResponsePayload []byte
	Status          uint8
	V               *big.Int
	R               *big.Int
	S               *big.Int
}

func (tx *RespondTx) copy() TxData {
	return &RespondTx{
		ChainID:         copyBigInt(tx.ChainID),
		Nonce:           tx.Nonce,
		GasTipCap:       copyBigInt(tx.GasTipCap),
		GasFeeCap:       copyBigInt(tx.GasFeeCap),
		Gas:             tx.Gas,
		WorkflowId:      tx.WorkflowId,
		StepId:          tx.StepId,
		InvokeRef:       tx.InvokeRef,
		ResponsePayload: common.CopyBytes(tx.ResponsePayload),
		Status:          tx.Status,
		V:               copyBigInt(tx.V),
		R:               copyBigInt(tx.R),
		S:               copyBigInt(tx.S),
	}
}

func (tx *RespondTx) txType() byte           { return RespondTxType }
func (tx *RespondTx) chainID() *big.Int      { return tx.ChainID }
func (tx *RespondTx) accessList() AccessList { return nil }
func (tx *RespondTx) data() []byte           { return tx.ResponsePayload }
func (tx *RespondTx) gas() uint64            { return tx.Gas }
func (tx *RespondTx) gasFeeCap() *big.Int    { return tx.GasFeeCap }
func (tx *RespondTx) gasTipCap() *big.Int    { return tx.GasTipCap }
func (tx *RespondTx) gasPrice() *big.Int     { return tx.GasFeeCap }
func (tx *RespondTx) value() *big.Int        { return new(big.Int) }
func (tx *RespondTx) nonce() uint64          { return tx.Nonce }
func (tx *RespondTx) to() *common.Address {
	addr := params.AGNT2InteractionPrecompileAddress
	return &addr
}
func (tx *RespondTx) isSystemTx() bool { return false }

func (tx *RespondTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	return agnt2EffectiveGasPrice(dst, tx.GasFeeCap, tx.GasTipCap, baseFee)
}

func (tx *RespondTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *RespondTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID, tx.V, tx.R, tx.S = chainID, v, r, s
}

func (tx *RespondTx) encode(b *bytes.Buffer) error {
	if err := tx.validate(); err != nil {
		return err
	}
	return rlp.Encode(b, tx)
}

func (tx *RespondTx) decode(input []byte) error {
	if err := rlp.DecodeBytes(input, tx); err != nil {
		return err
	}
	return tx.validate()
}

func (tx *RespondTx) sigHash(chainID *big.Int) common.Hash {
	return prefixedRlpHash(
		RespondTxType,
		[]any{
			chainID,
			tx.Nonce,
			tx.GasTipCap,
			tx.GasFeeCap,
			tx.Gas,
			tx.WorkflowId,
			tx.StepId,
			tx.InvokeRef,
			tx.ResponsePayload,
			tx.Status,
		})
}

func (tx *RespondTx) validate() error {
	if len(tx.ResponsePayload) > Agnt2MaxPayloadBytes {
		return ErrAgnt2PayloadTooLarge
	}
	if tx.Status > 2 {
		return ErrAgnt2InvalidStatus
	}
	return nil
}
