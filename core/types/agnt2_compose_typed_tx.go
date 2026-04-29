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
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// ComposeTypedTx is the AGNT2 0x7C typed transaction.
type ComposeTypedTx struct {
	ChainID           *big.Int
	Nonce             uint64
	GasTipCap         *big.Int
	GasFeeCap         *big.Int
	Gas               uint64
	WorkflowId        common.Hash
	StepCount         uint8
	StepWorkflowRoots []common.Hash
	Payouts           []*big.Int
	V                 *big.Int
	R                 *big.Int
	S                 *big.Int
}

func (tx *ComposeTypedTx) copy() TxData {
	return &ComposeTypedTx{
		ChainID:           copyBigInt(tx.ChainID),
		Nonce:             tx.Nonce,
		GasTipCap:         copyBigInt(tx.GasTipCap),
		GasFeeCap:         copyBigInt(tx.GasFeeCap),
		Gas:               tx.Gas,
		WorkflowId:        tx.WorkflowId,
		StepCount:         tx.StepCount,
		StepWorkflowRoots: copyHashSlice(tx.StepWorkflowRoots),
		Payouts:           copyBigIntSlice(tx.Payouts),
		V:                 copyBigInt(tx.V),
		R:                 copyBigInt(tx.R),
		S:                 copyBigInt(tx.S),
	}
}

func (tx *ComposeTypedTx) txType() byte           { return ComposeTypedTxType }
func (tx *ComposeTypedTx) chainID() *big.Int      { return tx.ChainID }
func (tx *ComposeTypedTx) accessList() AccessList { return nil }
func (tx *ComposeTypedTx) data() []byte           { return nil }
func (tx *ComposeTypedTx) gas() uint64            { return tx.Gas }
func (tx *ComposeTypedTx) gasFeeCap() *big.Int    { return tx.GasFeeCap }
func (tx *ComposeTypedTx) gasTipCap() *big.Int    { return tx.GasTipCap }
func (tx *ComposeTypedTx) gasPrice() *big.Int     { return tx.GasFeeCap }
func (tx *ComposeTypedTx) value() *big.Int        { return new(big.Int) }
func (tx *ComposeTypedTx) nonce() uint64          { return tx.Nonce }
func (tx *ComposeTypedTx) to() *common.Address {
	addr := params.AGNT2InteractionPrecompileAddress
	return &addr
}
func (tx *ComposeTypedTx) isSystemTx() bool { return false }

func (tx *ComposeTypedTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	return agnt2EffectiveGasPrice(dst, tx.GasFeeCap, tx.GasTipCap, baseFee)
}

func (tx *ComposeTypedTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *ComposeTypedTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID, tx.V, tx.R, tx.S = chainID, v, r, s
}

func (tx *ComposeTypedTx) validate() error {
	if int(tx.StepCount) != len(tx.StepWorkflowRoots) {
		return errors.New("AGNT2: ComposeTypedTx StepWorkflowRoots length must equal StepCount")
	}
	if int(tx.StepCount) != len(tx.Payouts) {
		return errors.New("AGNT2: ComposeTypedTx Payouts length must equal StepCount")
	}
	return nil
}

func (tx *ComposeTypedTx) encode(b *bytes.Buffer) error {
	if err := tx.validate(); err != nil {
		return err
	}
	return rlp.Encode(b, tx)
}

func (tx *ComposeTypedTx) decode(input []byte) error {
	if err := rlp.DecodeBytes(input, tx); err != nil {
		return err
	}
	return tx.validate()
}

func (tx *ComposeTypedTx) sigHash(chainID *big.Int) common.Hash {
	return prefixedRlpHash(
		ComposeTypedTxType,
		[]any{
			chainID,
			tx.Nonce,
			tx.GasTipCap,
			tx.GasFeeCap,
			tx.Gas,
			tx.WorkflowId,
			tx.StepCount,
			tx.StepWorkflowRoots,
			tx.Payouts,
		})
}
