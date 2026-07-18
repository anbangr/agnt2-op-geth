// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// Package agnt2store implements the B2' cross-block re-execution store: a bounded,
// state-trie-committed ring of recent INVOKE committedOutputHashes so a later-block
// RESPOND's parent (RespondTx.InvokeRef) resolves cross-block in FoldTypedReexecRoot.
//
// CONSENSUS SAFETY (chain-split guard): the store lives in the reserved account
// params.AGNT2ReexecStoreAddr's storage, so it is bound into header.Root and is
// identical on every node that agrees on the state root — full importer, producer,
// reorg re-execution, AND the stateless fault-proof verifier (which builds a real
// StateDB from the witness). The write hook runs ONLY in beacon.Finalize (the single
// point both the producer and validator execute), so both paths reach the identical
// post-Finalize store. Reads (the resolver) touch only StateDB. Everything is a pure
// function of (state, header.Number, body.Transactions, cfg) — no wall-clock, mempool,
// receipt-availability, or node config — so producer and validator never diverge.
//
// BOUNDED (no unbounded growth): a ring of W=params.AGNT2ReexecWindow buckets, bucket
// b = blockNumber % W, evicted UNCONDITIONALLY every post-fork block before this
// block's own INVOKEs are written. An INVOKE in block M is resolvable for RESPONDs in
// [M, M+W-1]; older parents fall back to the M6 skip (documented residual escape).
package agnt2store

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// Domain-separated storage-slot namespaces (single-byte prefixes prevent collision).
func u256(x uint64) []byte { return common.BigToHash(new(big.Int).SetUint64(x)).Bytes() }

func slotOut(txHash common.Hash) common.Hash { return crypto.Keccak256Hash([]byte{0x01}, txHash[:]) } // -> committedOutputHash
func slotCnt(b uint64) common.Hash           { return crypto.Keccak256Hash([]byte{0x02}, u256(b)) }    // -> live entry count of bucket b
func slotMem(b, j uint64) common.Hash        { return crypto.Keccak256Hash([]byte{0x03}, u256(b), u256(j)) } // -> j-th txHash in bucket b (eviction reverse-index)
func slotBlk(txHash common.Hash) common.Hash { return crypto.Keccak256Hash([]byte{0x04}, txHash[:]) } // -> block number written (strictly-prior guard)

// ProcessReexecStore evicts ring bucket (header.Number % W) and writes this block's
// INVOKE outputs. Called ONLY from beacon.Finalize (symmetric across producer,
// validator, reorg re-exec, and the stateless verifier), gated on Optimism Isthmus.
// Eviction is UNCONDITIONAL (keeps the W-block horizon crisp); the write is skipped
// when the block has no INVOKEs.
func ProcessReexecStore(state vm.StateDB, cfg *params.ChainConfig, header *types.Header, txs []*types.Transaction) {
	if cfg == nil || !cfg.IsOptimismIsthmus(header.Time) {
		return
	}
	addr := params.AGNT2ReexecStoreAddr
	w := params.AGNT2ReexecWindow
	n := header.Number.Uint64()
	b := n % w

	// EVICT bucket b's previous occupant (block n-w's INVOKEs) unconditionally.
	cnt := state.GetState(addr, slotCnt(b)).Big().Uint64()
	for j := uint64(0); j < cnt; j++ {
		mk := slotMem(b, j)
		txh := state.GetState(addr, mk)
		state.SetState(addr, slotOut(txh), common.Hash{})
		state.SetState(addr, slotBlk(txh), common.Hash{})
		state.SetState(addr, mk, common.Hash{})
	}
	if cnt != 0 {
		state.SetState(addr, slotCnt(b), common.Hash{})
	}

	// WRITE this block's INVOKE outputs, in block order. AGNT2InvokeReexecOutput is
	// the SAME single-source helper the fold's INVOKE branch uses -> stored value is
	// byte-identical to the same-block map value.
	signer := types.MakeSigner(cfg, header.Number, header.Time)
	blkHash := common.BigToHash(header.Number)
	var idx uint64
	for _, tx := range txs {
		committed, ok := types.AGNT2InvokeReexecOutput(tx, signer)
		if !ok {
			continue
		}
		if idx == 0 && state.GetNonce(addr) == 0 {
			// Lazy, idempotent seed: a storage-only account is empty() (ignores
			// storage) and would be deleted at IntermediateRoot(true). Nonce=1 keeps
			// the reserved account alive across evict-to-empty blocks.
			state.SetNonce(addr, 1, tracing.NonceChangeUnspecified)
		}
		th := tx.Hash()
		state.SetState(addr, slotOut(th), committed)
		state.SetState(addr, slotBlk(th), blkHash)
		state.SetState(addr, slotMem(b, idx), th)
		idx++
	}
	if idx != 0 {
		state.SetState(addr, slotCnt(b), common.BigToHash(new(big.Int).SetUint64(idx)))
	}
}

// Resolver returns a ReexecParentResolver reading the ring from committed state.
// curBlockNum is the block being folded; the STRICTLY-PRIOR guard (blk >= curBlockNum
// => miss) ensures a same-block parent is served only by the fold's in-block map,
// never the ring, so cross-block and same-block semantics stay disjoint on both paths.
func Resolver(state vm.StateDB, curBlockNum uint64) types.ReexecParentResolver {
	addr := params.AGNT2ReexecStoreAddr
	return func(invokeRef common.Hash) (common.Hash, bool) {
		blk := state.GetState(addr, slotBlk(invokeRef)).Big().Uint64()
		if blk == 0 || blk >= curBlockNum {
			return common.Hash{}, false // absent/evicted, or same-block/future (strictly-prior)
		}
		out := state.GetState(addr, slotOut(invokeRef))
		if out == (common.Hash{}) {
			return common.Hash{}, false
		}
		return out, true
	}
}
