// Copyright 2021 The go-ethereum Authors
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

package beacon

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core/agnt2store"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/internal/agnt2debug"
	"github.com/ethereum/go-ethereum/internal/telemetry"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
)

// Proof-of-stake protocol constants.
var (
	beaconDifficulty = common.Big0          // The default block difficulty in the beacon consensus
	beaconNonce      = types.EncodeNonce(0) // The default block nonce in the beacon consensus
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	errTooManyUncles    = errors.New("too many uncles")
	errInvalidNonce     = errors.New("invalid nonce")
	errInvalidUncleHash = errors.New("invalid uncle hash")
	errInvalidTimestamp = errors.New("invalid timestamp")
)

// Beacon is a consensus engine that combines the eth1 consensus and proof-of-stake
// algorithm. There is a special flag inside to decide whether to use legacy consensus
// rules or new rules. The transition rule is described in the eth1/2 merge spec.
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3675.md
//
// The beacon here is a half-functional consensus engine with partial functions which
// is only used for necessary consensus checks. The legacy consensus engine can be any
// engine implements the consensus interface (except the beacon itself).
type Beacon struct {
	// For migrated OP chains (OP mainnet, OP Goerli), ethone is a dummy legacy pre-Bedrock consensus
	ethone consensus.Engine // Original consensus engine used in eth1, e.g. ethash or clique
}

// New creates a consensus engine with the given embedded eth1 engine.
func New(ethone consensus.Engine) *Beacon {
	if _, ok := ethone.(*Beacon); ok {
		panic("nested consensus engine")
	}
	return &Beacon{ethone: ethone}
}

// Author implements consensus.Engine, returning the verified author of the block.
func (beacon *Beacon) Author(header *types.Header) (common.Address, error) {
	if !beacon.IsPoSHeader(header) {
		return beacon.ethone.Author(header)
	}
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules of the
// stock Ethereum consensus engine.
func (beacon *Beacon) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header) error {
	// During the live merge transition, the consensus engine used the terminal
	// total difficulty to detect when PoW (PoA) switched to PoS. Maintaining the
	// total difficulty values however require applying all the blocks from the
	// genesis to build up the TD. This stops being a possibility if the tail of
	// the chain is pruned already during sync.
	//
	// One heuristic that can be used to distinguish pre-merge and post-merge
	// blocks is whether their *difficulty* is >0 or ==0 respectively. This of
	// course would mean that we cannot prove anymore for a past chain that it
	// truly transitioned at the correct TTD, but if we consider that ancient
	// point in time finalized a long time ago, there should be no attempt from
	// the consensus client to rewrite very old history.
	//
	// One thing that's probably not needed but which we can add to make this
	// verification even stricter is to enforce that the chain can switch from
	// >0 to ==0 TD only once by forbidding an ==0 to be followed by a >0.

	// Verify that we're not reverting to pre-merge from post-merge
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	if parent.Difficulty.Sign() == 0 && header.Difficulty.Sign() > 0 {
		return consensus.ErrInvalidTerminalBlock
	}
	cfg := chain.Config()
	// Check >0 TDs with pre-merge, --0 TDs with post-merge rules
	if header.Difficulty.Sign() > 0 ||
		// OP-Stack: transitioned networks must use legacy consensus pre-Bedrock
		cfg.IsOptimismPreBedrock(header.Number) {
		return beacon.ethone.VerifyHeader(chain, header)
	}
	return beacon.verifyHeader(chain, header, parent)
}

// OP-Stack Bedrock variant of splitHeaders: the total-terminal difficulty is terminated at bedrock transition, but also reset to 0.
// So just use the bedrock fork check to split the headers, to simplify the splitting.
// The returned slices are slices over the input. The input must be sorted.
func (beacon *Beacon) splitBedrockHeaders(chain consensus.ChainHeaderReader, headers []*types.Header) ([]*types.Header, []*types.Header) {
	for i, h := range headers {
		if chain.Config().IsBedrock(h.Number) {
			return headers[:i], headers[i:]
		}
	}
	return headers, nil
}

// splitHeaders splits the provided header batch into two parts according to
// the difficulty field.
//
// Note, this function will not verify the header validity but just split them.
func (beacon *Beacon) splitHeaders(chain consensus.ChainHeaderReader, headers []*types.Header) ([]*types.Header, []*types.Header) {
	if chain.Config().IsOptimism() {
		return beacon.splitBedrockHeaders(chain, headers)
	}

	var (
		preHeaders  = headers
		postHeaders []*types.Header
	)
	for i, header := range headers {
		if header.Difficulty.Sign() == 0 {
			preHeaders = headers[:i]
			postHeaders = headers[i:]
			break
		}
	}
	return preHeaders, postHeaders
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications.
// VerifyHeaders expect the headers to be ordered and continuous.
func (beacon *Beacon) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header) (chan<- struct{}, <-chan error) {
	preHeaders, postHeaders := beacon.splitHeaders(chain, headers)
	if len(postHeaders) == 0 {
		return beacon.ethone.VerifyHeaders(chain, headers)
	}
	if len(preHeaders) == 0 {
		return beacon.verifyHeaders(chain, headers, nil)
	}
	// The transition point exists in the middle, separate the headers
	// into two batches and apply different verification rules for them.
	var (
		abort   = make(chan struct{})
		results = make(chan error, len(headers))
	)
	go func() {
		var (
			old, new, out      = 0, len(preHeaders), 0
			errors             = make([]error, len(headers))
			done               = make([]bool, len(headers))
			oldDone, oldResult = beacon.ethone.VerifyHeaders(chain, preHeaders)
			newDone, newResult = beacon.verifyHeaders(chain, postHeaders, preHeaders[len(preHeaders)-1])
		)
		// Collect the results
		for {
			for ; done[out]; out++ {
				results <- errors[out]
				if out == len(headers)-1 {
					return
				}
			}
			select {
			case err := <-oldResult:
				if !done[old] { // skip TTD-verified failures
					errors[old], done[old] = err, true
				}
				old++
			case err := <-newResult:
				errors[new], done[new] = err, true
				new++
			case <-abort:
				close(oldDone)
				close(newDone)
				return
			}
		}
	}()
	return abort, results
}

// VerifyUncles verifies that the given block's uncles conform to the consensus
// rules of the Ethereum consensus engine.
func (beacon *Beacon) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if !beacon.IsPoSHeader(block.Header()) {
		return beacon.ethone.VerifyUncles(chain, block)
	}
	// Verify that there is no uncle block. It's explicitly disabled in the beacon
	if len(block.Uncles()) > 0 {
		return errTooManyUncles
	}
	return nil
}

// verifyHeader checks whether a header conforms to the consensus rules of the
// stock Ethereum consensus engine. The difference between the beacon and classic is
// (a) The following fields are expected to be constants:
//   - difficulty is expected to be 0
//   - nonce is expected to be 0
//   - unclehash is expected to be Hash(emptyHeader)
//     to be the desired constants
//
// (b) we don't verify if a block is in the future anymore
// (c) the extradata is limited to 32 bytes
func (beacon *Beacon) verifyHeader(chain consensus.ChainHeaderReader, header, parent *types.Header) error {
	// Ensure that the header's extra-data section is of a reasonable size
	if len(header.Extra) > int(params.MaximumExtraDataSize) {
		return fmt.Errorf("extra-data longer than 32 bytes (%d)", len(header.Extra))
	}
	// Validate Optimism extraData format (skip genesis block which may have non-empty extraData)
	if chain.Config().IsOptimism() && !chain.Config().IsOptimismGenesisBlock(header.Number) {
		if err := eip1559.ValidateOptimismExtraData(chain.Config(), header.Time, header.Extra); err != nil {
			return fmt.Errorf("invalid optimism extraData: %w", err)
		}
	}
	// Verify the seal parts. Ensure the nonce and uncle hash are the expected value.
	if header.Nonce != beaconNonce {
		return errInvalidNonce
	}
	if header.UncleHash != types.EmptyUncleHash {
		return errInvalidUncleHash
	}
	// Verify the timestamp
	if header.Time <= parent.Time {
		return errInvalidTimestamp
	}
	// Verify the block's difficulty to ensure it's the default constant
	if beaconDifficulty.Cmp(header.Difficulty) != 0 {
		return fmt.Errorf("invalid difficulty: have %v, want %v", header.Difficulty, beaconDifficulty)
	}
	// Verify that the gas limit is <= 2^63-1
	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}
	// Verify that the block number is parent's +1
	if diff := new(big.Int).Sub(header.Number, parent.Number); diff.Cmp(common.Big1) != 0 {
		return consensus.ErrInvalidNumber
	}
	// Verify the header's EIP-1559 attributes.
	if err := eip1559.VerifyEIP1559Header(chain.Config(), parent, header); err != nil {
		return err
	}
	// Verify existence / non-existence of withdrawalsHash.
	shanghai := chain.Config().IsShanghai(header.Number, header.Time)
	if shanghai && header.WithdrawalsHash == nil {
		return errors.New("missing withdrawalsHash")
	}
	if !shanghai && header.WithdrawalsHash != nil {
		return fmt.Errorf("invalid withdrawalsHash: have %x, expected nil", header.WithdrawalsHash)
	}
	// Verify the existence / non-existence of cancun-specific header fields
	cancun := chain.Config().IsCancun(header.Number, header.Time)
	if !cancun {
		switch {
		case header.ExcessBlobGas != nil:
			return fmt.Errorf("invalid excessBlobGas: have %d, expected nil", *header.ExcessBlobGas)
		case header.BlobGasUsed != nil:
			return fmt.Errorf("invalid blobGasUsed: have %d, expected nil", *header.BlobGasUsed)
		case header.ParentBeaconRoot != nil:
			return fmt.Errorf("invalid parentBeaconRoot, have %#x, expected nil", *header.ParentBeaconRoot)
		}
	} else {
		if header.ParentBeaconRoot == nil {
			return errors.New("header is missing beaconRoot")
		}
		if err := eip4844.VerifyEIP4844Header(chain.Config(), parent, header); err != nil {
			return err
		}
	}

	amsterdam := chain.Config().IsAmsterdam(header.Number, header.Time)
	if amsterdam && header.SlotNumber == nil {
		return errors.New("header is missing slotNumber")
	}
	if !amsterdam && header.SlotNumber != nil {
		return fmt.Errorf("invalid slotNumber: have %d, expected nil", *header.SlotNumber)
	}
	// AGNT2 Week 11 Phase 7: existence/non-existence of the interaction-MMR
	// header fields. Both must be present together post-Isthmus (the AGNT2
	// fork tag, matching the precompile registry init). Pre-Isthmus blocks
	// MUST NOT carry these fields — older nodes that decode such headers
	// via rlp:"optional" treat trailing data as absent and would diverge.
	agnt2Active := chain.Config().IsOptimismIsthmus(header.Time)
	if agnt2Active {
		if header.InteractionRoot == nil {
			return errors.New("header is missing interactionRoot")
		}
		if header.InteractionCount == nil {
			return errors.New("header is missing interactionCount")
		}
	} else {
		if header.InteractionRoot != nil {
			return fmt.Errorf("invalid interactionRoot: have %x, expected nil", header.InteractionRoot)
		}
		if header.InteractionCount != nil {
			return fmt.Errorf("invalid interactionCount: have %d, expected nil", *header.InteractionCount)
		}
		// TypedOpRoot/TypedOpCount are also AGNT2 extension fields — reject pre-fork.
		if header.TypedOpRoot != nil {
			return fmt.Errorf("invalid typedOpRoot: have %x, expected nil pre-fork", header.TypedOpRoot)
		}
		if header.TypedOpCount != nil {
			return fmt.Errorf("invalid typedOpCount: have %d, expected nil pre-fork", *header.TypedOpCount)
		}
	}
	return nil
}

// verifyHeaders is similar to verifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications. An additional parent
// header will be passed if the relevant header is not in the database yet.
func (beacon *Beacon) verifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, ancestor *types.Header) (chan<- struct{}, <-chan error) {
	var (
		abort   = make(chan struct{})
		results = make(chan error, len(headers))
	)
	go func() {
		for i, header := range headers {
			var parent *types.Header
			if i == 0 {
				if ancestor != nil {
					parent = ancestor
				} else {
					parent = chain.GetHeader(headers[0].ParentHash, headers[0].Number.Uint64()-1)
				}
			} else if headers[i-1].Hash() == headers[i].ParentHash {
				parent = headers[i-1]
			}
			if parent == nil {
				select {
				case <-abort:
					return
				case results <- consensus.ErrUnknownAncestor:
				}
				continue
			}
			err := beacon.verifyHeader(chain, header, parent)
			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// Prepare implements consensus.Engine, initializing the difficulty field of a
// header to conform to the beacon protocol. The changes are done inline.
func (beacon *Beacon) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	if !chain.Config().IsPostMerge(header.Number.Uint64(), header.Time) {
		return beacon.ethone.Prepare(chain, header)
	}
	header.Difficulty = beaconDifficulty
	return nil
}

// Finalize implements consensus.Engine and processes withdrawals on top.
func (beacon *Beacon) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state vm.StateDB, body *types.Body) {
	if !beacon.IsPoSHeader(header) {
		beacon.ethone.Finalize(chain, header, state, body)
		return
	}
	// Withdrawals processing.
	for _, w := range body.Withdrawals {
		// Convert amount from gwei to wei.
		amount := new(uint256.Int).SetUint64(w.Amount)
		amount = amount.Mul(amount, uint256.NewInt(params.GWei))
		state.AddBalance(w.Address, amount, tracing.BalanceIncreaseWithdrawal)
	}
	// No block reward which is issued by consensus layer instead.

	// B2' cross-block re-exec store: evict ring bucket (N%W) + write this block's
	// INVOKE outputs so a later-block RESPOND resolves its parent INVOKE cross-block
	// in FoldTypedReexecRoot. Placed in beacon.Finalize (NOT FinalizeAndAssemble) so
	// it runs on BOTH the producer (FinalizeAndAssemble->Finalize) and the validator
	// (StateProcessor.Process->Finalize) paths, reaching an identical post-Finalize
	// state root. Isthmus-gated inside ProcessReexecStore.
	agnt2store.ProcessReexecStore(state, chain.Config(), header, body.Transactions)
}

// FinalizeAndAssemble implements consensus.Engine, setting the final state and
// assembling the block.
func (beacon *Beacon) FinalizeAndAssemble(ctx context.Context, chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, body *types.Body, receipts []*types.Receipt) (result *types.Block, err error) {
	ctx, _, spanEnd := telemetry.StartSpan(ctx, "consensus.beacon.FinalizeAndAssemble",
		telemetry.Int64Attribute("block.number", int64(header.Number.Uint64())),
		telemetry.Int64Attribute("txs.count", int64(len(body.Transactions))),
		telemetry.Int64Attribute("withdrawals.count", int64(len(body.Withdrawals))),
	)
	defer spanEnd(&err)

	if !beacon.IsPoSHeader(header) {
		block, delegateErr := beacon.ethone.FinalizeAndAssemble(ctx, chain, header, state, body, receipts)
		return block, delegateErr
	}
	shanghai := chain.Config().IsShanghai(header.Number, header.Time)
	if shanghai {
		// All blocks after Shanghai must include a withdrawals root.
		if body.Withdrawals == nil {
			body.Withdrawals = make([]*types.Withdrawal, 0)
		}
	} else {
		if len(body.Withdrawals) > 0 {
			return nil, errors.New("withdrawals set before Shanghai activation")
		}
	}
	// Finalize and assemble the block.
	_, _, finalizeSpanEnd := telemetry.StartSpan(ctx, "consensus.beacon.Finalize")
	beacon.Finalize(chain, header, state, body)
	finalizeSpanEnd(nil)

	// B2' cross-block WITNESS COMPLETENESS: the typed-op re-execution fold reads the
	// ring's parent-INVOKE slots (agnt2store.Resolver) from PRIOR blocks' buckets that
	// THIS block's Finalize/eviction never touches. Those reads MUST run BEFORE
	// IntermediateRoot(true) — the sole execution-witness collection pass — so the
	// parent slots' storage-trie nodes are captured in the shipped execution witness.
	// The validator folds before its own IntermediateRoot (block_validator.go), so this
	// keeps the producer SYMMETRIC: a witness-backed stateless verifier reads the same
	// ring and re-derives an identical TypedReexecRoot/Count (otherwise it would
	// M6-skip an honest cross-block RESPOND and reject an honest block). The fold only
	// READS state, so header.Root — computed from state just below — is unaffected.
	if chain.Config().IsOptimismIsthmus(header.Time) {
		reexecRoot, reexecCount := types.FoldTypedReexecRoot(
			body.Transactions, types.MakeSigner(chain.Config(), header.Number, header.Time),
			agnt2store.Resolver(state, header.Number.Uint64()),
		)
		if reexecCount > 0 {
			reexecRootCopy := reexecRoot
			reexecCountCopy := reexecCount
			header.TypedReexecRoot = &reexecRootCopy
			header.TypedReexecCount = &reexecCountCopy
		}
	}

	// Assign the final state root to header.
	_, _, rootSpanEnd := telemetry.StartSpan(ctx, "consensus.beacon.IntermediateRoot")
	header.Root = state.IntermediateRoot(true)
	rootSpanEnd(nil)

	if chain.Config().IsOptimismIsthmus(header.Time) {
		if body.Withdrawals == nil || len(body.Withdrawals) > 0 { // We verify nil/empty withdrawals in the CL pre-Isthmus
			return nil, fmt.Errorf("expected non-nil empty withdrawals operation list in Isthmus, but got: %v", body.Withdrawals)
		}
		// State-root has just been computed, we can get an accurate storage-root now.
		h := state.GetStorageRoot(params.OptimismL2ToL1MessagePasser)
		header.WithdrawalsHash = &h
		sa := state.AccessEvents()
		if sa != nil {
			sa.AddAccount(params.OptimismL2ToL1MessagePasser, false, math.MaxUint64) // include in execution witness
		}
	}

	// Store DA footprint in BlobGasUsed header field if it hasn't already been set yet.
	// Builder code may already calculate it during block building to avoid recalculating it here.
	if chain.Config().IsJovian(header.Time) && (header.BlobGasUsed == nil || *header.BlobGasUsed == 0) {
		daFootprint, err := types.CalcDAFootprint(body.Transactions)
		if err != nil {
			return nil, fmt.Errorf("error calculating DA footprint: %w", err)
		}
		header.BlobGasUsed = &daFootprint
	}

	// AGNT2 Week 11 Phase 7: populate the interaction MMR root + leaf count
	// header fields from the canonical receipt-derived fold. Sequencer-side
	// computation must match the verifier-side fold in block_validator.go;
	// both routes call types.FoldInteractionRoot to keep the canonical
	// (txIndex, logIndex) order consistent across sequencer and every
	// validator. Fork-gated by Optimism Isthmus to align with the precompile
	// activation tag in core/vm/agnt2_interaction.go init().
	if chain.Config().IsOptimismIsthmus(header.Time) {
		root, count := types.FoldInteractionRoot(receipts)
		hashCopy := root
		countCopy := count
		header.InteractionRoot = &hashCopy
		header.InteractionCount = &countCopy

		// E4.4: populate typed-op MMR root + count from the block's typed
		// transactions. Only set when typed txs are present; absent otherwise
		// so the optional RLP fields remain nil for compatibility blocks.
		typedRoot, typedCount := types.FoldTypedOpRoot(body.Transactions)
		if typedCount > 0 {
			// E4.6: allow test harness to inject a bad root for correctness testing.
			if badRoot, ok := agnt2debug.GetBadRoot(header.Number.Uint64()); ok {
				typedRoot = badRoot
			}
			rootCopy := typedRoot
			countCopy2 := typedCount
			header.TypedOpRoot = &rootCopy
			header.TypedOpCount = &countCopy2
		}
		// NOTE: the B2' typed-op re-execution fold (header.TypedReexecRoot/Count) is
		// computed EARLIER, before IntermediateRoot, so its ring reads are captured in
		// the execution witness (see the witness-completeness note above). It is NOT
		// recomputed here.
	}

	// Assemble the final block.
	_, _, blockSpanEnd := telemetry.StartSpan(ctx, "consensus.beacon.NewBlock")
	block := types.NewBlock(header, body, receipts, trie.NewStackTrie(nil), chain.Config())
	blockSpanEnd(nil)
	return block, nil
}

// Seal generates a new sealing request for the given input block and pushes
// the result into the given channel.
//
// Note, the method returns immediately and will send the result async. More
// than one result may also be returned depending on the consensus algorithm.
func (beacon *Beacon) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	if !beacon.IsPoSHeader(block.Header()) {
		return beacon.ethone.Seal(chain, block, results, stop)
	}
	// The seal verification is done by the external consensus engine,
	// return directly without pushing any block back. In another word
	// beacon won't return any result by `results` channel which may
	// blocks the receiver logic forever.
	return nil
}

// SealHash returns the hash of a block prior to it being sealed.
func (beacon *Beacon) SealHash(header *types.Header) common.Hash {
	return beacon.ethone.SealHash(header)
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time
// given the parent block's time and difficulty.
func (beacon *Beacon) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	if !chain.Config().IsPostMerge(parent.Number.Uint64()+1, time) {
		return beacon.ethone.CalcDifficulty(chain, time, parent)
	}
	return beaconDifficulty
}

// Close shutdowns the consensus engine
func (beacon *Beacon) Close() error {
	return beacon.ethone.Close()
}

// IsPoSHeader reports the header belongs to the PoS-stage with some special fields.
// This function is not suitable for a part of APIs like Prepare or CalcDifficulty
// because the header difficulty is not set yet.
func (beacon *Beacon) IsPoSHeader(header *types.Header) bool {
	if header.Difficulty == nil {
		panic("IsPoSHeader called with invalid difficulty")
	}
	return header.Difficulty.Cmp(beaconDifficulty) == 0
}

// InnerEngine returns the embedded eth1 consensus engine.
func (beacon *Beacon) InnerEngine() consensus.Engine {
	return beacon.ethone
}

func (beacon *Beacon) SwapInner(inner consensus.Engine) {
	beacon.ethone = inner
}

// SetThreads updates the mining threads. Delegate the call
// to the eth1 engine if it's threaded.
func (beacon *Beacon) SetThreads(threads int) {
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := beacon.ethone.(threaded); ok {
		th.SetThreads(threads)
	}
}
