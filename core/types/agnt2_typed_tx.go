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
	"errors"
	"math/big"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/text/unicode/norm"
)

const (
	Agnt2MaxAgentRoleBytes = 64
	Agnt2MaxPayloadBytes   = 16 * 1024
	Agnt2TypedTxPerStepGas = 2000
)

var (
	ErrAgnt2AgentRoleTooLong = errors.New("agnt2 agent role exceeds 64 bytes")
	ErrAgnt2AgentRoleUTF8    = errors.New("agnt2 agent role must be valid UTF-8")
	ErrAgnt2AgentRoleNFC     = errors.New("agnt2 agent role must be NFC-normalized")
	ErrAgnt2PayloadTooLarge  = errors.New("agnt2 payload exceeds 16 KiB")
	ErrAgnt2DepInvokeIdsNil  = errors.New("agnt2 dep invoke ids cannot be nil")
	ErrAgnt2InvalidStatus    = errors.New("agnt2 respond status must be 0, 1, or 2")
)

func validateAgnt2AgentRole(role string) error {
	if len(role) > Agnt2MaxAgentRoleBytes {
		return ErrAgnt2AgentRoleTooLong
	}
	if !utf8.ValidString(role) {
		return ErrAgnt2AgentRoleUTF8
	}
	if !norm.NFC.IsNormalString(role) {
		return ErrAgnt2AgentRoleNFC
	}
	return nil
}

func copyBigInt(v *big.Int) *big.Int {
	if v == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(v)
}

func copyHashSlice(in []common.Hash) []common.Hash {
	if in == nil {
		return nil
	}
	out := make([]common.Hash, len(in))
	copy(out, in)
	return out
}

func copyBigIntSlice(in []*big.Int) []*big.Int {
	if in == nil {
		return nil
	}
	out := make([]*big.Int, len(in))
	for i, v := range in {
		out[i] = copyBigInt(v)
	}
	return out
}

func agnt2EffectiveGasPrice(dst, gasFeeCap, gasTipCap, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(gasFeeCap)
	}
	tip := dst.Sub(gasFeeCap, baseFee)
	if tip.Cmp(gasTipCap) > 0 {
		tip.Set(gasTipCap)
	}
	return tip.Add(tip, baseFee)
}

// Agnt2IntrinsicGasSurcharge returns the typed-op state-write gas reserve.
func (tx *Transaction) Agnt2IntrinsicGasSurcharge() uint64 {
	switch itx := tx.inner.(type) {
	case *InvokeTx, *RespondTx:
		return Agnt2TypedTxPerStepGas
	case *ComposeTypedTx:
		return uint64(itx.StepCount) * Agnt2TypedTxPerStepGas
	default:
		return 0
	}
}
