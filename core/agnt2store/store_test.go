// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// Cross-block re-exec ring tests: an INVOKE written in block M resolves for a
// RESPOND in a LATER block via the state-committed ring; a same-block/future ref
// is rejected by the strictly-prior guard; a parent past the W-block horizon is
// evicted; and the ring survives a state-root round-trip (proving it is bound
// into header.Root — the property that keeps producer + validator symmetric).
package agnt2store

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

func newTestState(t *testing.T) (*state.StateDB, state.Database) {
	t.Helper()
	db := state.NewDatabaseForTesting()
	sdb, err := state.New(types.EmptyRootHash, db)
	if err != nil {
		t.Fatal(err)
	}
	return sdb, db
}

func mkHeader(n uint64) *types.Header {
	return &types.Header{Number: new(big.Int).SetUint64(n), Time: 0}
}

func mkInvoke(t *testing.T, cfg *params.ChainConfig, signer types.Signer, key *ecdsa.PrivateKey, nonce uint64, wf common.Hash) *types.Transaction {
	t.Helper()
	tx, err := types.SignNewTx(key, signer, &types.InvokeTx{
		ChainID: cfg.ChainID, Nonce: nonce, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
		Gas: 100000, WorkflowId: wf, StepId: 1, AgentRole: "worker", DepInvokeIds: []common.Hash{}, Payload: []byte("call"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// TestCrossBlockResolveAndStrictlyPrior: an INVOKE in block 100 is resolvable for
// a fold at block 101 (returns the SAME value the fold's INVOKE branch derives via
// AGNT2InvokeReexecOutput), but NOT for a fold at block 100 (same-block => served
// only by the in-block map) nor for an unknown ref.
func TestCrossBlockResolveAndStrictlyPrior(t *testing.T) {
	cfg := params.OptimismTestConfig
	sdb, _ := newTestState(t)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	h100 := mkHeader(100)
	signer := types.MakeSigner(cfg, h100.Number, h100.Time)
	inv := mkInvoke(t, cfg, signer, key, 0, common.HexToHash("0x77"))

	want, ok := types.AGNT2InvokeReexecOutput(inv, signer)
	if !ok {
		t.Fatal("AGNT2InvokeReexecOutput: not ok for a signed INVOKE")
	}

	ProcessReexecStore(sdb, cfg, h100, []*types.Transaction{inv})

	// Fold at block 101: resolves to the canonical committed output.
	got, present := Resolver(sdb, 101)(inv.Hash())
	if !present || got != want {
		t.Fatalf("cross-block resolve: present=%v got=%x want=%x", present, got, want)
	}
	// Fold at block 100 (same block): strictly-prior guard => miss.
	if _, p := Resolver(sdb, 100)(inv.Hash()); p {
		t.Fatal("strictly-prior guard failed: same-block ref resolved via the ring")
	}
	// Fold at block 99 (before the write): future-block guard => miss.
	if _, p := Resolver(sdb, 99)(inv.Hash()); p {
		t.Fatal("strictly-prior guard failed: a ref written by a LATER block resolved")
	}
	// Unknown ref => miss.
	if _, p := Resolver(sdb, 101)(common.HexToHash("0xdead")); p {
		t.Fatal("unknown ref resolved")
	}
}

// TestEvictionPastWindow: the same ring bucket (blockNumber % W) is reused every W
// blocks; block 100+W unconditionally evicts block 100's occupant, so its INVOKE is
// no longer resolvable — the documented residual escape (a parent older than W falls
// back to the M6 skip). The reserved account stays alive (Nonce=1 seed) even after
// eviction empties its storage.
func TestEvictionPastWindow(t *testing.T) {
	cfg := params.OptimismTestConfig
	w := params.AGNT2ReexecWindow
	sdb, _ := newTestState(t)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	h100 := mkHeader(100)
	signer := types.MakeSigner(cfg, h100.Number, h100.Time)
	inv := mkInvoke(t, cfg, signer, key, 0, common.HexToHash("0x77"))
	ProcessReexecStore(sdb, cfg, h100, []*types.Transaction{inv})

	// Still resolvable one block before the horizon closes.
	if _, p := Resolver(sdb, 100+w-1)(inv.Hash()); !p {
		t.Fatalf("INVOKE unexpectedly unresolvable at block %d (within window)", 100+w-1)
	}

	// Block 100+W reuses bucket 100%W and evicts the occupant (no INVOKEs of its own).
	ProcessReexecStore(sdb, cfg, mkHeader(100+w), nil)
	if _, p := Resolver(sdb, 100+w+1)(inv.Hash()); p {
		t.Fatal("eviction failed: parent past the W-block horizon still resolved")
	}
	// Nonce=1 seed keeps the storage-only reserved account alive across evict-to-empty.
	if n := sdb.GetNonce(params.AGNT2ReexecStoreAddr); n != 1 {
		t.Fatalf("reserved account nonce=%d want 1 (seed lost => account prunable)", n)
	}
}

// TestRingSurvivesStateRoot commits the state and reopens from the resulting root,
// proving the ring is bound into header.Root. This is the invariant that makes the
// producer's fold (over its Finalize state) and the validator's fold (over the
// re-derived state) read an identical ring — without it, cross-block folds diverge.
func TestRingSurvivesStateRoot(t *testing.T) {
	cfg := params.OptimismTestConfig
	sdb, db := newTestState(t)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	h100 := mkHeader(100)
	signer := types.MakeSigner(cfg, h100.Number, h100.Time)
	inv := mkInvoke(t, cfg, signer, key, 0, common.HexToHash("0x77"))
	want, _ := types.AGNT2InvokeReexecOutput(inv, signer)

	ProcessReexecStore(sdb, cfg, h100, []*types.Transaction{inv})
	root, err := sdb.Commit(100, true, false) // deleteEmptyObjects=true: proves the Nonce=1 seed survives
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := state.New(root, db)
	if err != nil {
		t.Fatal(err)
	}
	got, present := Resolver(reopened, 101)(inv.Hash())
	if !present || got != want {
		t.Fatalf("ring lost across state-root round-trip: present=%v got=%x want=%x", present, got, want)
	}
}

// TestFoldResolvesCrossBlockRespond is the end-to-end proof: a RESPOND in block 101
// whose parent INVOKE lived in block 100 is SKIPPED by FoldTypedReexecRoot under a
// nil resolver (the same-block-only M6 behavior) but FOLDS once the ring resolver is
// supplied — closing the loop store-write -> Resolver -> fold RESPOND branch.
func TestFoldResolvesCrossBlockRespond(t *testing.T) {
	cfg := params.OptimismTestConfig
	sdb, _ := newTestState(t)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	h100 := mkHeader(100)
	signer := types.MakeSigner(cfg, h100.Number, h100.Time)
	wf := common.HexToHash("0x99")
	inv := mkInvoke(t, cfg, signer, key, 0, wf)
	ProcessReexecStore(sdb, cfg, h100, []*types.Transaction{inv})

	// RESPOND in block 101 pointing at block-100's INVOKE (its parent).
	respond, err := types.SignNewTx(key, signer, &types.RespondTx{
		ChainID: cfg.ChainID, Nonce: 1, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
		Gas: 100000, WorkflowId: wf, StepId: 2, InvokeRef: inv.Hash(), ResponsePayload: []byte("resp"), Status: 0,
	})
	if err != nil {
		t.Fatal(err)
	}

	// nil resolver: the cross-block parent is unresolved => RESPOND skipped (M6).
	if _, count := types.FoldTypedReexecRoot([]*types.Transaction{respond}, signer, nil); count != 0 {
		t.Fatalf("nil resolver: count=%d want 0 (cross-block RESPOND must skip)", count)
	}
	// ring resolver: parent resolves from block 100 => RESPOND folds.
	if _, count := types.FoldTypedReexecRoot([]*types.Transaction{respond}, signer, Resolver(sdb, 101)); count != 1 {
		t.Fatalf("ring resolver: count=%d want 1 (cross-block RESPOND resolves + folds)", count)
	}
}
