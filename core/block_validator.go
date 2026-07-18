// Copyright 2015 The go-ethereum Authors
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

package core

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/agnt2store"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

// Agnt2InvalidSignatureCount counts blocks rejected by AGNT2 typed-op
// validation. Exported for metrics and test assertions; safe for concurrent
// access.
var Agnt2InvalidSignatureCount atomic.Uint64

// BlockValidator is responsible for validating block headers, uncles and
// processed state.
//
// BlockValidator implements Validator.
type BlockValidator struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
}

// NewBlockValidator returns a new block validator which is safe for re-use
func NewBlockValidator(config *params.ChainConfig, blockchain *BlockChain) *BlockValidator {
	validator := &BlockValidator{
		config: config,
		bc:     blockchain,
	}
	return validator
}

// ValidateBody validates the given block's uncles and verifies the block
// header's transaction and uncle roots. The headers are assumed to be already
// validated at this point.
func (v *BlockValidator) ValidateBody(block *types.Block) error {
	// check EIP 7934 RLP-encoded block size cap
	if v.config.IsOsaka(block.Number(), block.Time()) && block.Size() > params.MaxBlockSize {
		return ErrBlockOversized
	}
	// Check whether the block is already imported.
	if v.bc.HasBlockAndState(block.Hash(), block.NumberU64()) {
		return ErrKnownBlock
	}

	// Header validity is known at this point. Here we verify that uncles, transactions
	// and withdrawals given in the block body match the header.
	header := block.Header()
	if err := v.bc.engine.VerifyUncles(v.bc, block); err != nil {
		return err
	}
	if hash := types.CalcUncleHash(block.Uncles()); hash != header.UncleHash {
		return fmt.Errorf("uncle root hash mismatch (header value %x, calculated %x)", header.UncleHash, hash)
	}
	if hash := types.DeriveSha(block.Transactions(), trie.NewStackTrie(nil)); hash != header.TxHash {
		return fmt.Errorf("transaction root hash mismatch (header value %x, calculated %x)", header.TxHash, hash)
	}

	// Withdrawals are present after the Shanghai fork.
	if header.WithdrawalsHash != nil {
		// Withdrawals list must be present in body after Shanghai.
		if block.Withdrawals() == nil {
			return errors.New("missing withdrawals in block body")
		}
		if v.config.IsOptimismIsthmus(header.Time) {
			if len(block.Withdrawals()) > 0 {
				return errors.New("no withdrawal block-operations allowed, withdrawalsRoot is set to storage root")
			}
			// The withdrawalsHash is verified in ValidateState, like the state root, as verification requires state merkleization.
		} else if hash := types.DeriveSha(block.Withdrawals(), trie.NewStackTrie(nil)); hash != *header.WithdrawalsHash {
			return fmt.Errorf("withdrawals root hash mismatch (header value %s, calculated %s)", *header.WithdrawalsHash, hash)
		}
	} else if block.Withdrawals() != nil {
		// Withdrawals are not allowed prior to Shanghai fork
		return errors.New("withdrawals present in block body")
	}

	// Blob transactions may be present after the Cancun fork.
	var blobs int
	for i, tx := range block.Transactions() {
		// Count the number of blobs to validate against the header's blobGasUsed
		blobs += len(tx.BlobHashes())

		// If the tx is a blob tx, it must NOT have a sidecar attached to be valid in a block.
		if tx.BlobTxSidecar() != nil {
			return fmt.Errorf("unexpected blob sidecar in transaction at index %d", i)
		}

		// The individual checks for blob validity (version-check + not empty)
		// happens in state transition.
	}

	// Check blob gas usage.
	if !v.config.IsOptimism() && header.BlobGasUsed != nil {
		if want := *header.BlobGasUsed / params.BlobTxBlobGasPerBlob; uint64(blobs) != want { // div because the header is surely good vs the body might be bloated
			return fmt.Errorf("blob gas used mismatch (header %v, calculated %v)", *header.BlobGasUsed, blobs*params.BlobTxBlobGasPerBlob)
		}
	} else {
		if blobs > 0 {
			return errors.New("data blobs present in block body")
		}
	}

	// OP Stack Jovian DA footprint block limit.
	if v.config.IsJovian(header.Time) {
		if header.BlobGasUsed == nil {
			return errors.New("nil blob gas used in post-Jovian block header, should store DA footprint")
		}
		blobGasUsed := *header.BlobGasUsed
		daFootprint, err := types.CalcDAFootprint(block.Transactions())
		if err != nil {
			return fmt.Errorf("failed to calculate DA footprint: %w", err)
		} else if blobGasUsed != daFootprint {
			return fmt.Errorf("invalid DA footprint in blobGasUsed field (remote: %d local: %d)", blobGasUsed, daFootprint)
		}
		if daFootprint > block.GasLimit() {
			return fmt.Errorf("DA footprint %d exceeds block gas limit %d", daFootprint, block.GasLimit())
		}
	}

	// Ancestor block must be known.
	if !v.bc.HasBlockAndState(block.ParentHash(), block.NumberU64()-1) {
		if !v.bc.HasBlock(block.ParentHash(), block.NumberU64()-1) {
			return consensus.ErrUnknownAncestor
		}
		return consensus.ErrPrunedAncestor
	}
	return nil
}

// ValidateState validates the various changes that happen after a state transition,
// such as amount of used gas, the receipt roots and the state root itself.
func (v *BlockValidator) ValidateState(block *types.Block, statedb *state.StateDB, res *ProcessResult, stateless bool) error {
	if res == nil {
		return errors.New("nil ProcessResult value")
	}
	header := block.Header()
	if block.GasUsed() != res.GasUsed {
		return fmt.Errorf("invalid gas used (remote: %d local: %d)", block.GasUsed(), res.GasUsed)
	}
	// Validate the received block's bloom with the one derived from the generated receipts.
	// For valid blocks this should always validate to true.
	//
	// Receipts must go through MakeReceipt to calculate the receipt's bloom
	// already. Merge the receipt's bloom together instead of recalculating
	// everything.
	rbloom := types.MergeBloom(res.Receipts)
	if rbloom != header.Bloom {
		return fmt.Errorf("invalid bloom (remote: %x  local: %x)", header.Bloom, rbloom)
	}
	// AGNT2 Week 11 Phase 7: validate the interaction MMR root + leaf count
	// declared in the header against the receipt-derived fold. Runs BEFORE the
	// stateless early-return — receipts cross-check is a consensus rule that
	// applies to both full and stateless paths. Without this ordering, a
	// malicious sequencer could forge the InteractionRoot and pass the
	// stateless fault-proof validation path (Codex Phase 6+7 review #1, P1).
	// Logic lives in validateAGNT2InteractionFields so it can be unit-tested
	// in isolation from the full ValidateState scaffolding.
	if err := validateAGNT2InteractionFields(header, res.Receipts); err != nil {
		return err
	}
	if err := validateAGNT2TypedOpFields(header, block.Transactions()); err != nil {
		return err
	}
	if err := validateAGNT2TypedReexecFields(
		header, block.Transactions(), types.MakeSigner(v.config, block.Number(), block.Time()),
		agnt2store.Resolver(statedb, block.NumberU64()),
	); err != nil {
		return err
	}
	if err := validateAGNT2TypedOpOrder(block.Transactions()); err != nil {
		return err
	}
	// In stateless mode, return early because the receipt and state root are not
	// provided through the witness, rather the cross validator needs to return it.
	if stateless {
		return nil
	}
	// The receipt Trie's root (R = (Tr [[H1, R1], ... [Hn, Rn]]))
	receiptSha := types.DeriveSha(res.Receipts, trie.NewStackTrie(nil))
	if receiptSha != header.ReceiptHash {
		return fmt.Errorf("invalid receipt root hash (remote: %x local: %x)", header.ReceiptHash, receiptSha)
	}
	// Validate the parsed requests match the expected header value.
	if header.RequestsHash != nil {
		reqhash := types.CalcRequestsHash(res.Requests)
		if reqhash != *header.RequestsHash {
			return fmt.Errorf("invalid requests hash (remote: %x local: %x)", *header.RequestsHash, reqhash)
		}
	} else if res.Requests != nil {
		return errors.New("block has requests before prague fork")
	}
	// Validate the state root against the received state root and throw
	// an error if they don't match.
	if root := statedb.IntermediateRoot(v.config.IsEIP158(header.Number)); header.Root != root {
		return fmt.Errorf("invalid merkle root (remote: %x local: %x) dberr: %w", header.Root, root, statedb.Error())
	}
	if v.config.IsOptimismIsthmus(block.Time()) {
		if header.WithdrawalsHash == nil {
			return errors.New("expected withdrawals root in OP-Stack post-Isthmus block header")
		}
		// Validate the withdrawals root against the L2 withdrawals storage, similar to how the StateRoot is verified.
		if root := statedb.GetStorageRoot(params.OptimismL2ToL1MessagePasser); *header.WithdrawalsHash != root {
			return fmt.Errorf("invalid withdrawals hash (remote: %s local: %s) dberr: %w", *header.WithdrawalsHash, root, statedb.Error())
		}
	}
	return nil
}

// validateAGNT2InteractionFields enforces the Phase 7 contract: when a
// header declares (InteractionRoot, InteractionCount), both must be
// present and both must reproduce from the canonical receipt-derived fold.
// Pre-fork blocks (absent fields) skip the branch — existence per fork
// is enforced separately in consensus/beacon verifyHeader. Returning a
// non-nil error means block import MUST reject this block.
func validateAGNT2InteractionFields(header *types.Header, receipts []*types.Receipt) error {
	if header.InteractionRoot == nil && header.InteractionCount == nil {
		return nil
	}
	if header.InteractionRoot == nil || header.InteractionCount == nil {
		return errors.New("AGNT2: interactionRoot and interactionCount must both be present or both absent")
	}
	gotRoot, gotCount := types.FoldInteractionRoot(receipts)
	if gotRoot != *header.InteractionRoot {
		return fmt.Errorf("AGNT2: invalid interaction root (remote: %x local: %x)", *header.InteractionRoot, gotRoot)
	}
	if gotCount != *header.InteractionCount {
		return fmt.Errorf("AGNT2: invalid interaction count (remote: %d local: %d)", *header.InteractionCount, gotCount)
	}
	return nil
}

// validateAGNT2TypedOpFields enforces the E4.4 contract: when a header
// declares (TypedOpRoot, TypedOpCount), both must be present and both must
// reproduce from the canonical typed-transaction fold. Half-pair (one nil,
// one non-nil) is always rejected.
func validateAGNT2TypedOpFields(header *types.Header, txs []*types.Transaction) error {
	if header.TypedOpRoot == nil && header.TypedOpCount == nil {
		return nil
	}
	if header.TypedOpRoot == nil || header.TypedOpCount == nil {
		return errors.New("AGNT2: typedOpRoot and typedOpCount must both be present or both absent")
	}
	gotRoot, gotCount := types.FoldTypedOpRoot(txs)
	if gotRoot != *header.TypedOpRoot {
		Agnt2InvalidSignatureCount.Add(1)
		return fmt.Errorf("AGNT2: invalid typed-op root (remote: %x local: %x)", *header.TypedOpRoot, gotRoot)
	}
	if gotCount != *header.TypedOpCount {
		return fmt.Errorf("AGNT2: invalid typed-op count (remote: %d local: %d)", *header.TypedOpCount, gotCount)
	}
	return nil
}

// validateAGNT2TypedReexecFields enforces the B2' contract: when a header declares
// (TypedReexecRoot, TypedReexecCount), both must be present and both must reproduce
// from the canonical typed-op re-execution fold (FoldTypedReexecRoot). Half-pair
// (one nil, one non-nil) is always rejected. Runs on both the full-node and the
// stateless fault-proof import paths so the L1 fraud gate can trust the committed
// re-exec root.
func validateAGNT2TypedReexecFields(header *types.Header, txs []*types.Transaction, signer types.Signer, resolver types.ReexecParentResolver) error {
	gotRoot, gotCount := types.FoldTypedReexecRoot(txs, signer, resolver)
	if header.TypedReexecRoot == nil && header.TypedReexecCount == nil {
		// A block with foldable INVOKE/RESPOND ops MUST commit the reexec root. A nil
		// pair with a non-empty fold is a producer omitting the fraud commitment (the
		// M4 omission escape — now that RESPOND is non-vacuous, omission would let a
		// fraudulent op escape re-execution). Only a genuinely-empty fold may omit.
		if gotCount > 0 {
			Agnt2InvalidSignatureCount.Add(1)
			return fmt.Errorf("AGNT2: typedReexecRoot/Count absent but %d foldable typed op(s) present", gotCount)
		}
		return nil
	}
	if header.TypedReexecRoot == nil || header.TypedReexecCount == nil {
		return errors.New("AGNT2: typedReexecRoot and typedReexecCount must both be present or both absent")
	}
	if gotRoot != *header.TypedReexecRoot {
		Agnt2InvalidSignatureCount.Add(1)
		return fmt.Errorf("AGNT2: invalid typed-reexec root (remote: %x local: %x)", *header.TypedReexecRoot, gotRoot)
	}
	if gotCount != *header.TypedReexecCount {
		return fmt.Errorf("AGNT2: invalid typed-reexec count (remote: %d local: %d)", *header.TypedReexecCount, gotCount)
	}
	return nil
}

func validateAGNT2TypedOpOrder(txs []*types.Transaction) error {
	inBlock := make(map[common.Hash]int)
	// workflowSteps maps a WorkflowId to the in-block INVOKE/RESPOND step hashes
	// carrying it, in block order. It lets us enforce that a COMPOSE settling a
	// workflow appears after every same-workflow step present in this block (G1).
	workflowSteps := make(map[common.Hash][]common.Hash)
	for i, tx := range txs {
		switch tx.Type() {
		case types.InvokeTxType, types.RespondTxType, types.ComposeTypedTxType:
			inBlock[tx.Hash()] = i
		}
		// Agnt2OperationID is ok only for INVOKE/RESPOND — the workflow's steps.
		if opId, ok := tx.Agnt2OperationID(); ok {
			workflowSteps[opId.WorkflowId] = append(workflowSteps[opId.WorkflowId], tx.Hash())
		}
	}
	if len(inBlock) == 0 {
		return nil
	}

	seen := make(map[common.Hash]struct{}, len(inBlock))
	for i, tx := range txs {
		if _, ok := inBlock[tx.Hash()]; !ok {
			continue
		}
		// Explicit tx-hash dependencies (INVOKE.DepInvokeIds, RESPOND.InvokeRef).
		// Each in-block dependency must (a) reference an INVOKE and (b) precede
		// this tx. Cross-block dependencies are ordered by block sequence and
		// skipped here (mirrors the historical behavior).
		for _, dep := range tx.Agnt2Dependencies() {
			depIndex, ok := inBlock[dep]
			if !ok {
				continue
			}
			// Type-aware: a typed-op dependency must reference an INVOKE. A step
			// naming a RESPOND or COMPOSE as its dependency is malformed. Rejecting
			// it closes the compose-hash-dependency cycle the G1 same-workflow edge
			// would otherwise permit: a griefer could point their own INVOKE's
			// DepInvokeIds at the honest COMPOSE's hash, creating a dep edge
			// (compose -> step) that, combined with the same-workflow edge
			// (step -> compose), makes the ordering constraints unsatisfiable.
			if txs[depIndex].Type() != types.InvokeTxType {
				Agnt2InvalidSignatureCount.Add(1)
				return fmt.Errorf("AGNT2: invalid typed-op dependency at tx index %d: dependency %s at tx index %d is not an INVOKE", i, dep, depIndex)
			}
			if _, seenDep := seen[dep]; !seenDep {
				Agnt2InvalidSignatureCount.Add(1)
				return fmt.Errorf("AGNT2: invalid typed-op dependency order at tx index %d: dependency %s appears later at tx index %d", i, dep, depIndex)
			}
		}
		// G1: a COMPOSE(W) must appear after every in-block INVOKE/RESPOND with
		// WorkflowId==W. A COMPOSE settles exactly one workflow (the precompile
		// reverts any leaf whose workflow id differs), so same-workflow steps are
		// its constituents. This is a within-block guarantee: cross-block
		// constituents are naturally absent from workflowSteps (unconstrained,
		// mirroring the cross-block dependency skip above), and it assumes the
		// producer does not reuse one WorkflowId across two distinct in-block
		// settlements — true under a single honest sequencer.
		if wfID, ok := tx.Agnt2ComposeWorkflowId(); ok {
			for _, stepHash := range workflowSteps[wfID] {
				if _, seenStep := seen[stepHash]; !seenStep {
					Agnt2InvalidSignatureCount.Add(1)
					return fmt.Errorf("AGNT2: invalid typed-op dependency order at tx index %d: workflow %s constituent %s appears later at tx index %d", i, wfID, stepHash, inBlock[stepHash])
				}
			}
		}
		seen[tx.Hash()] = struct{}{}
	}
	return nil
}

// CalcGasLimit computes the gas limit of the next block after parent. It aims
// to keep the baseline gas close to the provided target, and increase it towards
// the target if the baseline gas is lower.
func CalcGasLimit(parentGasLimit, desiredLimit uint64) uint64 {
	delta := parentGasLimit/params.GasLimitBoundDivisor - 1
	limit := parentGasLimit
	if desiredLimit < params.MinGasLimit {
		desiredLimit = params.MinGasLimit
	}
	// If we're outside our allowed gas range, we try to hone towards them
	if limit < desiredLimit {
		limit = parentGasLimit + delta
		if limit > desiredLimit {
			limit = desiredLimit
		}
		return limit
	}
	if limit > desiredLimit {
		limit = parentGasLimit - delta
		if limit < desiredLimit {
			limit = desiredLimit
		}
	}
	return limit
}
