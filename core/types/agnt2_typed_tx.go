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
	"github.com/ethereum/go-ethereum/params"
	"golang.org/x/text/unicode/norm"
)

const (
	Agnt2MaxAgentRoleBytes = 64
	Agnt2MaxPayloadBytes   = 16 * 1024
	// Agnt2TypedTxPerStepGas is the base per-typed-op intrinsic-gas reserve for the
	// in-memory typed-op / re-exec root commitments.
	Agnt2TypedTxPerStepGas = 2000
	// Agnt2ReexecRingWriteGas prices the B2' cross-block re-exec ring WRITE that
	// beacon.Finalize performs for every INVOKE: 3 cold zero->nonzero SSTOREs (slotOut,
	// slotBlk, slotMem) into the state-committed ring so a later-block RESPOND can
	// resolve this INVOKE's committedOutputHash. That work runs in Finalize and is NOT
	// EVM-metered, so this surcharge charges the INVOKE sender for it at admission,
	// closing the cheap-typed-tx state-spam DoS. The ring is bounded (W buckets, evicted
	// every W blocks) so state does not grow without bound, but the transient per-INVOKE
	// I/O must still be priced. Sized at 3 x (SSTORE-set + cold-slot access).
	Agnt2ReexecRingWriteGas = 3 * (params.SstoreSetGas + params.ColdSloadCostEIP2929)
	// Agnt2ReexecRingReadGas prices the RESPOND resolver's 2 cold SLOADs (slotBlk +
	// slotOut) during the cross-block fold — also non-EVM-metered. Charged to every
	// RESPOND as a conservative upper bound (only a cross-block parent actually reads).
	Agnt2ReexecRingReadGas = 2 * params.ColdSloadCostEIP2929
)

var (
	ErrAgnt2AgentRoleEmpty   = errors.New("agnt2 agent role must not be empty")
	ErrAgnt2AgentRoleTooLong = errors.New("agnt2 agent role exceeds 64 bytes")
	ErrAgnt2AgentRoleUTF8    = errors.New("agnt2 agent role must be valid UTF-8")
	ErrAgnt2AgentRoleNFC     = errors.New("agnt2 agent role must be NFC-normalized")
	ErrAgnt2PayloadTooLarge  = errors.New("agnt2 payload exceeds 16 KiB")
	ErrAgnt2DepInvokeIdsNil  = errors.New("agnt2 dep invoke ids cannot be nil")
	ErrAgnt2InvalidStatus    = errors.New("agnt2 respond status must be 0, 1, or 2")
)

func validateAgnt2AgentRole(role string) error {
	if len(role) == 0 {
		return ErrAgnt2AgentRoleEmpty
	}
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

// Agnt2IntrinsicGasSurcharge returns the typed-op intrinsic-gas reserve, including
// the B2' cross-block re-exec ring cost: an INVOKE additionally reserves the ring
// WRITE (its output is SSTOREd in beacon.Finalize for later-block resolution); a
// RESPOND additionally reserves the ring READ (its resolver SLOADs the parent). Both
// happen outside EVM metering, so the sender pays here at admission (DoS pricing).
//
// FORK-GATING (pre-mainnet TODO): the ring surcharge is currently unconditional while
// the work it prices (ProcessReexecStore) is Isthmus-gated. This is safe today because
// the typed-op re-exec feature is unlaunched — no live chain has typed-tx blocks that
// were validated under the old (2000-only) surcharge. Before any chain with typed-tx
// history upgrades into this code, the increased surcharge MUST be gated to a fork
// boundary (at the application sites, state_transition.go / txpool/validation.go, which
// have the chain rules) so re-validating historical blocks does not change gasUsed and
// split old vs new nodes.
func (tx *Transaction) Agnt2IntrinsicGasSurcharge() uint64 {
	switch itx := tx.inner.(type) {
	case *InvokeTx:
		return Agnt2TypedTxPerStepGas + Agnt2ReexecRingWriteGas
	case *RespondTx:
		return Agnt2TypedTxPerStepGas + Agnt2ReexecRingReadGas
	case *ComposeTypedTx:
		// COMPOSE does not touch the INVOKE-only ring (Stage 5 scope).
		return uint64(itx.StepCount) * Agnt2TypedTxPerStepGas
	default:
		return 0
	}
}

func (tx *Transaction) ValidateAgnt2Envelope() error {
	switch itx := tx.inner.(type) {
	case *InvokeTx:
		return itx.validate()
	case *RespondTx:
		return itx.validate()
	default:
		return nil
	}
}

type Agnt2OperationID struct {
	Type       uint8
	WorkflowId common.Hash
	StepId     uint8
}

func (tx *Transaction) Agnt2OperationID() (Agnt2OperationID, bool) {
	switch itx := tx.inner.(type) {
	case *InvokeTx:
		return Agnt2OperationID{Type: tx.Type(), WorkflowId: itx.WorkflowId, StepId: itx.StepId}, true
	case *RespondTx:
		return Agnt2OperationID{Type: tx.Type(), WorkflowId: itx.WorkflowId, StepId: itx.StepId}, true
	default:
		return Agnt2OperationID{}, false
	}
}

// Agnt2Dependencies returns the list of transaction hashes this transaction depends on.
func (tx *Transaction) Agnt2Dependencies() []common.Hash {
	switch itx := tx.inner.(type) {
	case *InvokeTx:
		return itx.DepInvokeIds
	case *RespondTx:
		return []common.Hash{itx.InvokeRef}
	case *ComposeTypedTx:
		return nil
	default:
		return nil
	}
}

// Agnt2ComposeWorkflowId returns the WorkflowId a ComposeTypedTx settles. ok is
// true ONLY for *ComposeTypedTx; every other tx type returns (zero, false).
//
// This is deliberately a separate accessor from Agnt2OperationID (which returns
// ok=false for COMPOSE and is load-bearing for the builder's operation-id dedup):
// it is a pure read-only accessor over an already-signed field and does NOT touch
// encode/decode/sigHash, so signed COMPOSE txs, golden fixtures, and the TS signer
// are unaffected. It backs the G1 rule that a COMPOSE(W) must appear after every
// in-block INVOKE/RESPOND with WorkflowId==W (its constituents).
func (tx *Transaction) Agnt2ComposeWorkflowId() (common.Hash, bool) {
	if itx, ok := tx.inner.(*ComposeTypedTx); ok {
		return itx.WorkflowId, true
	}
	return common.Hash{}, false
}
