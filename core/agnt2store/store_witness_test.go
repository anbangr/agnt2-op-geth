// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// Producer witness-completeness regression guard. The cross-block reexec fold reads
// the ring's prior-block parent-INVOKE slots via the resolver. Those reads MUST run
// BEFORE IntermediateRoot (the execution-witness collection pass) so the parent slots
// are captured in the shipped execution witness; the validator already folds before
// its IntermediateRoot, so the producer must match. If it does not, a witness-backed
// stateless verifier rebuilds a StateDB that is MISSING those slots, the resolver
// reports a miss, the RESPOND is M6-skipped, and the verifier re-derives a different
// TypedReexecRoot/Count than the honest header committed — rejecting an honest block
// (the C0b honest-deposit-drain class this whole gate exists to close).
//
// This test rebuilds a StateDB from ONLY the collected witness and checks the resolver
// against it: reads-before-root => the parent resolves (fix); reads-after-root =>
// the parent is absent from the witness (the bug), proving the test detects it.
package agnt2store

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/stateless"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
)

// fakeHeaderReader supplies the single parent header stateless.NewWitness needs
// (Headers[0].Root becomes the witness's rebuild root).
type fakeHeaderReader struct{ parent *types.Header }

func (f fakeHeaderReader) GetHeader(hash common.Hash, number uint64) *types.Header { return f.parent }

func TestProducerWitnessCapturesCrossBlockParent(t *testing.T) {
	cfg := params.OptimismTestConfig
	db := state.NewDatabaseForTesting()
	sdb, err := state.New(types.EmptyRootHash, db)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	// Block M=100: publish an INVOKE into the ring, commit -> r0 (the parent state).
	hM := mkHeader(100)
	signer := types.MakeSigner(cfg, hM.Number, hM.Time)
	inv := mkInvoke(t, cfg, signer, key, 0, common.HexToHash("0x77"))
	want, ok := types.AGNT2InvokeReexecOutput(inv, signer)
	if !ok {
		t.Fatal("AGNT2InvokeReexecOutput not ok")
	}
	ProcessReexecStore(sdb, cfg, hM, []*types.Transaction{inv})
	r0, err := sdb.Commit(100, true, false)
	if err != nil {
		t.Fatal(err)
	}

	// Build a block-N=101 execution witness over state r0, running its own Finalize
	// store hook (so 0xA9E2 is a mutated object, exactly as in a real block) and the
	// cross-block resolver read at the given position relative to IntermediateRoot.
	buildWitness := func(readBeforeRoot bool) *stateless.Witness {
		s, err := state.New(r0, db)
		if err != nil {
			t.Fatal(err)
		}
		parent := &types.Header{Number: big.NewInt(100), Root: r0}
		ctx := &types.Header{Number: big.NewInt(101), ParentHash: parent.Hash()}
		w, err := stateless.NewWitness(ctx, fakeHeaderReader{parent}, false)
		if err != nil {
			t.Fatal(err)
		}
		s.StartPrefetcher("test", w)
		// Block N's own Finalize store hook (bucket 101, disjoint from M's bucket 100).
		hN := mkHeader(101)
		invN := mkInvoke(t, cfg, types.MakeSigner(cfg, hN.Number, hN.Time), key, 1, common.HexToHash("0x88"))
		ProcessReexecStore(s, cfg, hN, []*types.Transaction{invN})
		if readBeforeRoot {
			Resolver(s, 101)(inv.Hash()) // producer order: read the cross-block parent BEFORE root
		}
		s.IntermediateRoot(true) // witness collection pass
		if !readBeforeRoot {
			Resolver(s, 101)(inv.Hash()) // buggy order: read AFTER collection
		}
		s.StopPrefetcher()
		return w
	}

	rebuildAndResolve := func(w *stateless.Witness) (common.Hash, bool, error) {
		memdb := w.MakeHashDB()
		reb, err := state.New(w.Root(), state.NewDatabase(triedb.NewDatabase(memdb, triedb.HashDefaults), state.NewCodeDB(memdb)))
		if err != nil {
			return common.Hash{}, false, err
		}
		out, present := Resolver(reb, 101)(inv.Hash())
		return out, present, nil
	}

	// Positive: fixed order (read before root) -> witness complete -> rebuilt resolver hits.
	got, present, err := rebuildAndResolve(buildWitness(true))
	if err != nil {
		t.Fatalf("rebuild from fixed-order witness failed: %v", err)
	}
	if !present || got != want {
		t.Fatalf("producer witness (fixed order) missing cross-block parent: present=%v got=%x want=%x", present, got, want)
	}

	// Negative control: buggy order (read after root) -> witness omits the parent slots.
	// The rebuilt StateDB either errors on the missing trie node or the resolver misses;
	// either outcome proves the parent's slots are absent (so the test detects the bug).
	got2, present2, err2 := rebuildAndResolve(buildWitness(false))
	if err2 == nil && present2 {
		t.Fatalf("negative control failed: read-after-IntermediateRoot witness resolved the parent (got=%x) — the test would not catch the bug", got2)
	}
}
