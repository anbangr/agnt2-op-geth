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

// InvokeTx is the AGNT2 0x7A typed transaction.
type InvokeTx struct {
	ChainID      *big.Int
	Nonce        uint64
	GasTipCap    *big.Int
	GasFeeCap    *big.Int
	Gas          uint64
	WorkflowId   common.Hash
	StepId       uint8
	AgentRole    string
	DepInvokeIds []common.Hash
	Payload      []byte
	V            *big.Int
	R            *big.Int
	S            *big.Int
}

func (tx *InvokeTx) copy() TxData {
	return &InvokeTx{
		ChainID:      copyBigInt(tx.ChainID),
		Nonce:        tx.Nonce,
		GasTipCap:    copyBigInt(tx.GasTipCap),
		GasFeeCap:    copyBigInt(tx.GasFeeCap),
		Gas:          tx.Gas,
		WorkflowId:   tx.WorkflowId,
		StepId:       tx.StepId,
		AgentRole:    tx.AgentRole,
		DepInvokeIds: copyHashSlice(tx.DepInvokeIds),
		Payload:      common.CopyBytes(tx.Payload),
		V:            copyBigInt(tx.V),
		R:            copyBigInt(tx.R),
		S:            copyBigInt(tx.S),
	}
}

func (tx *InvokeTx) txType() byte           { return InvokeTxType }
func (tx *InvokeTx) chainID() *big.Int      { return tx.ChainID }
func (tx *InvokeTx) accessList() AccessList { return nil }
func (tx *InvokeTx) data() []byte           { return tx.Payload }
func (tx *InvokeTx) gas() uint64            { return tx.Gas }
func (tx *InvokeTx) gasFeeCap() *big.Int    { return tx.GasFeeCap }
func (tx *InvokeTx) gasTipCap() *big.Int    { return tx.GasTipCap }
func (tx *InvokeTx) gasPrice() *big.Int     { return tx.GasFeeCap }
func (tx *InvokeTx) value() *big.Int        { return new(big.Int) }
func (tx *InvokeTx) nonce() uint64          { return tx.Nonce }
func (tx *InvokeTx) to() *common.Address {
	addr := params.AGNT2InteractionPrecompileAddress
	return &addr
}
func (tx *InvokeTx) isSystemTx() bool { return false }

func (tx *InvokeTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	return agnt2EffectiveGasPrice(dst, tx.GasFeeCap, tx.GasTipCap, baseFee)
}

func (tx *InvokeTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *InvokeTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID, tx.V, tx.R, tx.S = chainID, v, r, s
}

func (tx *InvokeTx) encode(b *bytes.Buffer) error {
	if err := tx.validate(); err != nil {
		return err
	}
	return rlp.Encode(b, tx)
}

func (tx *InvokeTx) decode(input []byte) error {
	if err := rlp.DecodeBytes(input, tx); err != nil {
		return err
	}
	return tx.validate()
}

func (tx *InvokeTx) sigHash(chainID *big.Int) common.Hash {
	return prefixedRlpHash(
		InvokeTxType,
		[]any{
			chainID,
			tx.Nonce,
			tx.GasTipCap,
			tx.GasFeeCap,
			tx.Gas,
			tx.WorkflowId,
			tx.StepId,
			tx.AgentRole,
			tx.DepInvokeIds,
			tx.Payload,
		})
}

func (tx *InvokeTx) validate() error {
	if err := validateAgnt2AgentRole(tx.AgentRole); err != nil {
		return err
	}
	if tx.DepInvokeIds == nil {
		return ErrAgnt2DepInvokeIdsNil
	}
	if len(tx.Payload) > Agnt2MaxPayloadBytes {
		return ErrAgnt2PayloadTooLarge
	}
	return nil
}
