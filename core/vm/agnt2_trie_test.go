package vm

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// agnt2_trie_test.go — WS3 unit + property tests for the interaction trie.
//
// T1 root parity (agnt2Trie vs bare agnt2MMR byte-identical)
// T2 inclusion proof verifies among >=1000 leaves
// T3 update proof old/new root differ + match pre/post roots
// T4 deterministic serialize round-trips (two independent builds)
// T5 header-fold unchanged (golden roots from the integrated path)
// + edge cases: empty trie, single leaf, non-power-of-2 counts {3,5,100,1000,10000},
//   duplicate interactionKey last-write, uint32 boundary stepIndex.

// leafHashesFromChain returns the per-leaf keccak hashes for n chained leaves
// (the same hashing the precompile does on leafBytes), so tests can build a
// trie/MMR over the identical leaf sequence the production path produces.
func leafHashesFromChain(wfHash []byte, n int) [][32]byte {
	raw := makeChainedLeaves(wfHash, n)
	out := make([][32]byte, n)
	for i := 0; i < n; i++ {
		var h [32]byte
		copy(h[:], crypto.Keccak256(raw[i*160:(i+1)*160]))
		out[i] = h
	}
	return out
}

// buildTrieFromChain appends n chained leaves through the O(1) Append hot path
// with typed keys derived from (wfHash, stepIndex), returning the trie. (Bulk
// loading uses Append, not the proof-building AppendTyped, so corpus
// construction stays O(n) rather than O(n^2); proofs are built on demand via
// Prove. The T3 update-proof test exercises AppendTyped directly.)
func buildTrieFromChain(wfHash []byte, n int) *agnt2Trie {
	var wf32 [32]byte
	copy(wf32[:], wfHash)
	hashes := leafHashesFromChain(wfHash, n)
	t := newAgnt2Trie()
	for i := 0; i < n; i++ {
		t.Append(interactionKey(wf32, uint32(i)), hashes[i])
	}
	return t
}

// buildBareMMRFromChain appends the same n leaf hashes to a bare agnt2MMR.
func buildBareMMRFromChain(wfHash []byte, n int) *agnt2MMR {
	hashes := leafHashesFromChain(wfHash, n)
	m := &agnt2MMR{}
	for i := 0; i < n; i++ {
		m.append(hashes[i])
	}
	return m
}

// --- T1: Root parity ---------------------------------------------------------

// TestAgnt2Trie_RootParity is the load-bearing regression: a root built through
// agnt2Trie.AppendTyped must be BYTE-IDENTICAL to the bare agnt2MMR.getRoot()
// over the same leaf sequence, across power-of-2 and non-power-of-2 counts.
func TestAgnt2Trie_RootParity(t *testing.T) {
	wfHash := crypto.Keccak256([]byte("parity-wf"))
	counts := []int{0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 100, 1000, 10000}
	for _, n := range counts {
		trie := buildTrieFromChain(wfHash, n)
		bare := buildBareMMRFromChain(wfHash, n)
		tr := trie.Root()
		br := bare.getRoot()
		if !bytes.Equal(tr[:], br[:]) {
			t.Fatalf("n=%d: trie root %x != bare MMR root %x", n, tr, br)
		}
	}
}

// TestAgnt2Trie_EmptyRoot — empty trie root == keccak256("") (agnt2_mmr.go:28-31).
func TestAgnt2Trie_EmptyRoot(t *testing.T) {
	trie := newAgnt2Trie()
	got := trie.Root()
	var want [32]byte
	copy(want[:], crypto.Keccak256([]byte{}))
	if got != want {
		t.Fatalf("empty trie root %x != keccak256(\"\") %x", got, want)
	}
	if trie.LeafCount() != 0 {
		t.Fatalf("empty trie leaf count = %d, want 0", trie.LeafCount())
	}
}

// TestAgnt2Trie_ProveMissingKey — Prove on a never-appended key returns false.
func TestAgnt2Trie_ProveMissingKey(t *testing.T) {
	wfHash := crypto.Keccak256([]byte("missing-wf"))
	trie := buildTrieFromChain(wfHash, 5)
	var wf32 [32]byte
	copy(wf32[:], wfHash)
	// Key for a step index that was never appended.
	_, ok := trie.Prove(interactionKey(wf32, 999))
	if ok {
		t.Fatalf("Prove on missing key returned ok=true")
	}
	// Empty trie: any key missing.
	empty := newAgnt2Trie()
	if _, ok := empty.Prove(interactionKey(wf32, 0)); ok {
		t.Fatalf("Prove on empty trie returned ok=true")
	}
}

// --- T2: Inclusion proof verifies among >=1000 leaves ------------------------

func TestAgnt2Trie_InclusionProofVerifies(t *testing.T) {
	wfHash := crypto.Keccak256([]byte("inclusion-wf"))
	var wf32 [32]byte
	copy(wf32[:], wfHash)
	n := 1000
	trie := buildTrieFromChain(wfHash, n)
	root := trie.Root()

	rng := rand.New(rand.NewSource(42))
	// Verify a spread of indices including boundaries + random picks.
	indices := []int{0, 1, 2, n / 2, n - 2, n - 1}
	for i := 0; i < 20; i++ {
		indices = append(indices, rng.Intn(n))
	}
	for _, idx := range indices {
		proof, ok := trie.Prove(interactionKey(wf32, uint32(idx)))
		if !ok {
			t.Fatalf("idx=%d: Prove returned ok=false", idx)
		}
		if proof.LeafIndex != uint64(idx) {
			t.Fatalf("idx=%d: proof.LeafIndex=%d", idx, proof.LeafIndex)
		}
		if !VerifyInclusion(proof, root, trie.LeafCount()) {
			t.Fatalf("idx=%d: inclusion proof did not recompute root %x", idx, root)
		}
		// Recomputed root must equal getRoot() exactly.
		got := recomputeRoot(proof.LeafHash, proof.Siblings, proof.LeafIndex, trie.LeafCount())
		if got != root {
			t.Fatalf("idx=%d: recomputeRoot %x != getRoot %x", idx, got, root)
		}
	}
}

// TestAgnt2Trie_InclusionProofTamperFails — a flipped sibling must NOT verify.
func TestAgnt2Trie_InclusionProofTamperFails(t *testing.T) {
	wfHash := crypto.Keccak256([]byte("tamper-wf"))
	var wf32 [32]byte
	copy(wf32[:], wfHash)
	trie := buildTrieFromChain(wfHash, 100)
	root := trie.Root()
	proof, ok := trie.Prove(interactionKey(wf32, 37))
	if !ok {
		t.Fatalf("Prove failed")
	}
	if len(proof.Siblings) == 0 {
		t.Fatalf("expected non-empty siblings for idx 37 among 100 leaves")
	}
	// Flip a bit in the first sibling.
	proof.Siblings[0][0] ^= 0xFF
	if VerifyInclusion(proof, root, trie.LeafCount()) {
		t.Fatalf("tampered proof unexpectedly verified")
	}
	// Wrong leaf hash also fails.
	proof2, _ := trie.Prove(interactionKey(wf32, 37))
	proof2.LeafHash[0] ^= 0xFF
	if VerifyInclusion(proof2, root, trie.LeafCount()) {
		t.Fatalf("tampered leaf hash unexpectedly verified")
	}
}

// TestAgnt2Trie_SingleLeafProof — single-leaf trie: inclusion proof has zero
// siblings and recomputes the root (which equals the leaf hash for n=1).
func TestAgnt2Trie_SingleLeafProof(t *testing.T) {
	wfHash := crypto.Keccak256([]byte("single-wf"))
	var wf32 [32]byte
	copy(wf32[:], wfHash)
	trie := buildTrieFromChain(wfHash, 1)
	root := trie.Root()
	hashes := leafHashesFromChain(wfHash, 1)
	if root != hashes[0] {
		t.Fatalf("single-leaf root %x != leaf hash %x", root, hashes[0])
	}
	proof, ok := trie.Prove(interactionKey(wf32, 0))
	if !ok {
		t.Fatalf("Prove failed on single leaf")
	}
	if len(proof.Siblings) != 0 {
		t.Fatalf("single-leaf proof should have 0 siblings, got %d", len(proof.Siblings))
	}
	if !VerifyInclusion(proof, root, 1) {
		t.Fatalf("single-leaf inclusion proof did not verify")
	}
}

// TestAgnt2Trie_NonPow2Counts — inclusion proofs verify across multi-peak
// (non-power-of-2) leaf counts: 3, 5, 100, 1000, 10000.
func TestAgnt2Trie_NonPow2Counts(t *testing.T) {
	wfHash := crypto.Keccak256([]byte("nonpow2-wf"))
	var wf32 [32]byte
	copy(wf32[:], wfHash)
	for _, n := range []int{3, 5, 100, 1000, 10000} {
		trie := buildTrieFromChain(wfHash, n)
		root := trie.Root()
		// Also assert parity with bare MMR for this count.
		bare := buildBareMMRFromChain(wfHash, n)
		if br := bare.getRoot(); br != root {
			t.Fatalf("n=%d: trie root %x != bare %x", n, root, br)
		}
		// Verify every index for small n; sample for large n.
		idxs := []int{0, 1, n - 1}
		if n > 16 {
			idxs = append(idxs, n/3, n/2, 2*n/3)
		} else {
			for i := 0; i < n; i++ {
				idxs = append(idxs, i)
			}
		}
		for _, idx := range idxs {
			if idx < 0 || idx >= n {
				continue
			}
			proof, ok := trie.Prove(interactionKey(wf32, uint32(idx)))
			if !ok {
				t.Fatalf("n=%d idx=%d: Prove failed", n, idx)
			}
			if !VerifyInclusion(proof, root, trie.LeafCount()) {
				t.Fatalf("n=%d idx=%d: inclusion proof did not verify", n, idx)
			}
		}
	}
}

// --- T3: Update proof witnesses one transition -------------------------------

func TestAgnt2Trie_UpdateProof(t *testing.T) {
	wfHash := crypto.Keccak256([]byte("update-wf"))
	var wf32 [32]byte
	copy(wf32[:], wfHash)
	hashes := leafHashesFromChain(wfHash, 50)

	trie := newAgnt2Trie()
	var prevRoot [32]byte
	copy(prevRoot[:], crypto.Keccak256([]byte{})) // empty-trie root before first append
	for i := 0; i < 50; i++ {
		preRoot := trie.Root()
		up := trie.AppendTyped(interactionKey(wf32, uint32(i)), hashes[i])
		postRoot := trie.Root()

		if up.OldRoot != preRoot {
			t.Fatalf("i=%d: UpdateProof.OldRoot %x != pre-append root %x", i, up.OldRoot, preRoot)
		}
		if up.NewRoot != postRoot {
			t.Fatalf("i=%d: UpdateProof.NewRoot %x != post-append root %x", i, up.NewRoot, postRoot)
		}
		if up.OldRoot == up.NewRoot {
			t.Fatalf("i=%d: UpdateProof old/new roots identical %x", i, up.OldRoot)
		}
		if up.NewLeaf != hashes[i] {
			t.Fatalf("i=%d: UpdateProof.NewLeaf %x != appended leaf %x", i, up.NewLeaf, hashes[i])
		}
		// The update proof's siblings must recompute the post-append root for
		// the freshly appended leaf.
		got := recomputeRoot(up.NewLeaf, up.Siblings, uint64(i), trie.LeafCount())
		if got != postRoot {
			t.Fatalf("i=%d: update-proof siblings recompute %x != post root %x", i, got, postRoot)
		}
		prevRoot = postRoot
	}
	_ = prevRoot
}

// --- T4: Deterministic serialization round-trips -----------------------------

func TestAgnt2Trie_SerializeDeterministic(t *testing.T) {
	wfHash := crypto.Keccak256([]byte("serialize-wf"))
	n := 10000
	a := buildTrieFromChain(wfHash, n)
	b := buildTrieFromChain(wfHash, n)
	sa := a.Serialize()
	sb := b.Serialize()
	if !bytes.Equal(sa, sb) {
		t.Fatalf("two independent builds serialized differently (len %d vs %d)", len(sa), len(sb))
	}
	// Header: 8-byte BE leaf count, then 32*n leaf bytes.
	if len(sa) != 8+32*n {
		t.Fatalf("serialize length = %d, want %d", len(sa), 8+32*n)
	}
	if binary.BigEndian.Uint64(sa[0:8]) != uint64(n) {
		t.Fatalf("serialize header count = %d, want %d", binary.BigEndian.Uint64(sa[0:8]), n)
	}
	// First leaf bytes must equal the first appended leaf hash.
	hashes := leafHashesFromChain(wfHash, n)
	if !bytes.Equal(sa[8:40], hashes[0][:]) {
		t.Fatalf("serialize first leaf mismatch")
	}
	// Empty trie serializes to 8 zero bytes.
	es := newAgnt2Trie().Serialize()
	if len(es) != 8 || binary.BigEndian.Uint64(es) != 0 {
		t.Fatalf("empty serialize = %x, want 8 zero bytes", es)
	}
}

// --- T5: Header fold unchanged ----------------------------------------------

// TestAgnt2Trie_HeaderFoldUnchanged asserts the integrated validateAndBuildMMR
// path still produces the locked golden roots (the same values asserted by
// TestRun_MMRRoot_v1_3step / v4_5step), proving the WS3 integration left the
// on-chain root byte-identical. These golden hex values are the canonical
// FoldInteractionRoot inputs; if the trie wrapper changed any combine order
// they would diverge.
func TestAgnt2Trie_HeaderFoldUnchanged(t *testing.T) {
	cases := []struct {
		name    string
		wfID    string
		steps   []struct{ stepID, agentRole string; payout uint64 }
		wantHex string
	}{
		{
			name: "v1_3step",
			wfID: "test-wf-001",
			steps: []struct{ stepID, agentRole string; payout uint64 }{
				{"step-1", "worker-a", 1000},
				{"step-2", "worker-b", 2000},
				{"step-3", "worker-c", 3000},
			},
			wantHex: "d54c19717603e20fbf82ff44e90eafd7d1ad14ef4d7811f8802cc3c078cc86c3",
		},
		{
			name: "v4_5step",
			wfID: "test-wf-005",
			steps: []struct{ stepID, agentRole string; payout uint64 }{
				{"step-1", "worker-a", 1000},
				{"step-2", "worker-b", 2000},
				{"step-3", "worker-c", 3000},
				{"step-4", "worker-d", 4000},
				{"step-5", "worker-e", 5000},
			},
			wantHex: "e34cda67eaf574138a02ab6ea87fd1ec55f8e3c09545f2c7c44edb8365316c91",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leavesBytes := makeCanonicalChain(tc.wfID, tc.steps)
			var flat []byte
			for _, l := range leavesBytes {
				flat = append(flat, l...)
			}
			input := makeInputWithLeaves(tc.wfID, flat)
			stepCount := uint64(binary.BigEndian.Uint32(input[1:5]))
			wfParsed, abiHeaderSize, _ := parseWorkflowID(input)
			root, _, errCode := validateAndBuildMMR(input, stepCount, abiHeaderSize, wfParsed)
			if errCode != 0 {
				t.Fatalf("validateAndBuildMMR err byte 0x%02x", errCode)
			}
			var want [32]byte
			copy(want[:], mustHex(t, tc.wantHex))
			if root != want {
				t.Fatalf("%s integrated root %x != golden %x", tc.name, root, want)
			}
		})
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi := hexNibble(t, s[2*i])
		lo := hexNibble(t, s[2*i+1])
		out[i] = hi<<4 | lo
	}
	return out
}

func hexNibble(t *testing.T, c byte) byte {
	t.Helper()
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		t.Fatalf("bad hex char %q", c)
		return 0
	}
}

// --- Edge cases --------------------------------------------------------------

// TestAgnt2Trie_DuplicateKeyLastWrite — appending the same interactionKey
// twice records the last write index; both leaves are still in the MMR (root
// reflects every append), and Prove returns the latest leaf.
func TestAgnt2Trie_DuplicateKeyLastWrite(t *testing.T) {
	wfHash := crypto.Keccak256([]byte("dup-wf"))
	var wf32 [32]byte
	copy(wf32[:], wfHash)
	trie := newAgnt2Trie()

	var leafA, leafB, leafC [32]byte
	copy(leafA[:], crypto.Keccak256([]byte("leaf-A")))
	copy(leafB[:], crypto.Keccak256([]byte("leaf-B")))
	copy(leafC[:], crypto.Keccak256([]byte("leaf-C")))

	key := interactionKey(wf32, 7)
	trie.AppendTyped(key, leafA)            // index 0
	trie.AppendTyped(interactionKey(wf32, 8), leafB) // index 1, different key
	trie.AppendTyped(key, leafC)            // index 2, SAME key as A -> last write

	if trie.LeafCount() != 3 {
		t.Fatalf("expected 3 appended leaves, got %d", trie.LeafCount())
	}
	proof, ok := trie.Prove(key)
	if !ok {
		t.Fatalf("Prove on duplicate key failed")
	}
	if proof.LeafIndex != 2 {
		t.Fatalf("duplicate key index = %d, want 2 (last write)", proof.LeafIndex)
	}
	if proof.LeafHash != leafC {
		t.Fatalf("duplicate key leaf = %x, want leafC %x", proof.LeafHash, leafC)
	}
	if !VerifyInclusion(proof, trie.Root(), trie.LeafCount()) {
		t.Fatalf("duplicate-key inclusion proof did not verify")
	}
}

// TestInteractionKey_Uint32Boundary — stepIndex packing handles 0, max-1, and
// the uint32 max boundary distinctly and matches the documented BE layout.
func TestInteractionKey_Uint32Boundary(t *testing.T) {
	var wf [32]byte
	copy(wf[:], crypto.Keccak256([]byte("boundary-wf")))

	cases := []uint32{0, 1, 255, 256, 65535, 65536, 1<<31 - 1, 1 << 31, 1<<32 - 2, 1<<32 - 1}
	seen := make(map[[32]byte]uint32)
	for _, si := range cases {
		k := interactionKey(wf, si)
		if prev, dup := seen[k]; dup {
			t.Fatalf("interactionKey collision: stepIndex %d and %d -> same key", prev, si)
		}
		seen[k] = si
		// Recompute the expected key manually to lock the byte layout.
		buf := make([]byte, 36)
		copy(buf[0:32], wf[:])
		binary.BigEndian.PutUint32(buf[32:36], si)
		var want [32]byte
		copy(want[:], crypto.Keccak256(buf))
		if k != want {
			t.Fatalf("stepIndex %d: interactionKey %x != BE-recompute %x", si, k, want)
		}
	}
	// Adjacent boundary values must differ at the LSB byte: max-1 vs max.
	if interactionKey(wf, 1<<32-1) == interactionKey(wf, 1<<32-2) {
		t.Fatalf("uint32 boundary keys collide")
	}
}

// TestRecomputeRoot_EmptyAndBadIndex — defensive paths: n=0 yields keccak256("")
// and an out-of-range index yields a non-verifying (zero-ish) recompute.
func TestRecomputeRoot_Defensive(t *testing.T) {
	var leaf [32]byte
	copy(leaf[:], crypto.Keccak256([]byte("x")))
	got := recomputeRoot(leaf, nil, 0, 0)
	var emptyRoot [32]byte
	copy(emptyRoot[:], crypto.Keccak256([]byte{}))
	if got != emptyRoot {
		t.Fatalf("recomputeRoot(n=0) = %x, want keccak256(\"\") %x", got, emptyRoot)
	}
	// Out-of-range index: should not match a real root.
	wfHash := crypto.Keccak256([]byte("defensive-wf"))
	trie := buildTrieFromChain(wfHash, 5)
	if recomputeRoot(leaf, nil, 99, trie.LeafCount()) == trie.Root() {
		t.Fatalf("out-of-range index unexpectedly matched root")
	}
}
