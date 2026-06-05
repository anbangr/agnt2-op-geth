package vm

import (
	"github.com/ethereum/go-ethereum/crypto"
)

// agnt2_trie.go extends the append-only MMR (agnt2_mmr.go) into the AGNT2
// "interaction trie": typed-invocation-state keys, inclusion proofs, update
// proofs, and deterministic serialization. It is purely additive — the
// embedded agnt2MMR remains the single source of truth for the on-chain root,
// so a root computed through agnt2Trie is BYTE-IDENTICAL to the bare
// agnt2MMR.getRoot() over the same leaf sequence (regression-locked by
// TestAgnt2Trie_RootParity). All keccak combining reuses the exact order in
// agnt2_mmr.go getRoot/buildTree:
//
//   - peaks are the bit-decomposition of n, largest-power-of-2 first
//     (descending from bit 31), each peak built left-to-right via buildTree
//   - peaks are folded right-to-left: keccak256(peak[i] || accumulator)
//
// so any root recomputed from a leaf + InclusionProof.Siblings matches
// getRoot() exactly.

// interactionKey derives the typed-invocation-state key for one step.
// keccak256(workflowIDHash || stepIndex_be32). Distinct from MMR position:
// the MMR orders leaves by append position, while interactionKey gives a
// stable typed address for one (workflow, step) invocation so external
// callers can Prove a leaf without knowing its append index. The big-endian
// uint32 packing matches the LeafEvent.StepIndex / log Data[28:32] layout in
// agnt2_emit.go so off-chain indexers derive the same key.
func interactionKey(workflowIDHash [32]byte, stepIndex uint32) [32]byte {
	buf := make([]byte, 36)
	copy(buf[0:32], workflowIDHash[:])
	buf[32] = byte(stepIndex >> 24)
	buf[33] = byte(stepIndex >> 16)
	buf[34] = byte(stepIndex >> 8)
	buf[35] = byte(stepIndex)
	var k [32]byte
	copy(k[:], crypto.Keccak256(buf))
	return k
}

// agnt2Trie wraps the append-only MMR with typed keys + proof emission. The
// embedded mmr is the authoritative root source (agnt2_mmr.go:16); keys maps
// each typed interactionKey to its leaf index. On duplicate key (same
// workflow + stepIndex appended twice) the last write wins — the new leaf is
// still appended to the MMR (so the root reflects every append), and keys
// points at the most recent index for that key (documented; not silently
// mismatched).
type agnt2Trie struct {
	mmr  agnt2MMR            // embedded existing primitive (agnt2_mmr.go:16)
	keys map[[32]byte]uint64 // interactionKey -> leaf index (last-write-wins)
}

// newAgnt2Trie returns an empty trie with an initialized key map.
func newAgnt2Trie() *agnt2Trie {
	return &agnt2Trie{keys: make(map[[32]byte]uint64)}
}

// InclusionProof recomputes the root from leaf + siblings (same combine order
// as agnt2_mmr.go getRoot/buildTree). Siblings are ordered bottom-up within
// the leaf's home peak, then the cross-peak fold siblings in the right-to-left
// order getRoot uses. The left/right side of each sibling is NOT stored: it is
// deterministically recoverable from (LeafIndex, leafCount) during verify, so
// the struct stays minimal and tamper-resistant (a verifier cannot be tricked
// by a forged side flag).
type InclusionProof struct {
	LeafIndex uint64
	LeafHash  [32]byte
	Siblings  [][32]byte
}

// UpdateProof witnesses one appended typed transition: the root before the
// append, the root after, the new leaf hash, and the cross-peak fold siblings
// of the new leaf in the post-append tree so an external verifier can confirm
// NewRoot follows from OldRoot + NewLeaf without re-reading every leaf.
type UpdateProof struct {
	OldRoot  [32]byte
	NewRoot  [32]byte
	NewLeaf  [32]byte
	Siblings [][32]byte
}

// Append adds one typed invocation: it appends the leaf to the embedded MMR
// (the root source) and records the typed interactionKey (last-write-wins on
// duplicates). It is the O(1)-amortized hot-path append used by the production
// typed-transition path (validateAndBuildMMR) — it does NOT build a proof, so
// per-leaf cost stays a single map insert + slice append. Callers that need a
// witness for the appended leaf call AppendTyped instead.
func (t *agnt2Trie) Append(key [32]byte, leafHash [32]byte) {
	if t.keys == nil {
		t.keys = make(map[[32]byte]uint64)
	}
	t.keys[key] = uint64(len(t.mmr.leaves))
	t.mmr.append(leafHash)
}

// AppendTyped appends one typed invocation and returns its update proof. The
// leaf is appended to the embedded MMR (so the root reflects it) and the key
// is recorded (last-write-wins on duplicates). The returned proof carries the
// pre- and post-append roots plus the inclusion siblings of the new leaf in
// the post-append tree. This recomputes peak roots, so it is O(n) per call —
// use it for explicit witness construction (the benchmark's
// inclusion_proof_build op, the T3 update-proof test), not for bulk corpus
// loading (use Append for that).
func (t *agnt2Trie) AppendTyped(key [32]byte, leafHash [32]byte) UpdateProof {
	old := t.mmr.getRoot()
	idx := uint64(len(t.mmr.leaves))
	t.Append(key, leafHash)
	newRoot := t.mmr.getRoot()
	// Inclusion siblings of the just-appended leaf in the post-append tree.
	sibs := t.siblingsForIndex(idx)
	return UpdateProof{OldRoot: old, NewRoot: newRoot, NewLeaf: leafHash, Siblings: sibs}
}

// Prove returns an inclusion proof for a previously appended key. The second
// return is false if the key was never appended (matches the spec's missing-key
// contract). The proof's Siblings recompute getRoot() exactly via
// VerifyInclusion / recomputeRoot.
func (t *agnt2Trie) Prove(key [32]byte) (InclusionProof, bool) {
	idx, ok := t.keys[key]
	if !ok {
		return InclusionProof{}, false
	}
	return InclusionProof{
		LeafIndex: idx,
		LeafHash:  t.mmr.leaves[idx],
		Siblings:  t.siblingsForIndex(idx),
	}, true
}

// Root exposes the current MMR root (the on-chain root source). Identical to
// the bare agnt2MMR.getRoot() over the same leaf sequence.
func (t *agnt2Trie) Root() [32]byte {
	return t.mmr.getRoot()
}

// LeafCount returns the number of appended leaves.
func (t *agnt2Trie) LeafCount() uint64 {
	return uint64(len(t.mmr.leaves))
}

// peakLayout returns, for a leaf count n, the descending-bit peak sizes (the
// same bit-decomposition getRoot uses: largest power-of-2 first) and the
// starting leaf offset of each peak. peaks[k] covers leaves[offsets[k] :
// offsets[k]+sizes[k]].
func peakLayout(n uint64) (sizes []uint64, offsets []uint64) {
	var offset uint64
	for bit := 31; bit >= 0; bit-- {
		size := uint64(1) << uint(bit)
		if n&size != 0 {
			sizes = append(sizes, size)
			offsets = append(offsets, offset)
			offset += size
		}
	}
	return sizes, offsets
}

// siblingsForIndex builds the ordered sibling list that lets a verifier
// recompute getRoot() from leaves[idx]. Order (matching getRoot's combine
// sequence):
//  1. bottom-up Merkle siblings inside the leaf's home peak (perfect tree,
//     left-to-right pairing via keccak256(left||right)) — getRoot/buildTree
//     order;
//  2. the single folded hash of every peak to the RIGHT of the home peak
//     (these fold right-to-left into one accumulator that sits on the home
//     peak's right), if any;
//  3. each peak to the LEFT of the home peak, nearest-left first, each sitting
//     on the running root's left (keccak256(leftPeak||root)).
//
// The left/right placement at each step is recoverable from (idx, n) so it is
// not stored in the proof.
func (t *agnt2Trie) siblingsForIndex(idx uint64) [][32]byte {
	n := uint64(len(t.mmr.leaves))
	if n == 0 || idx >= n {
		return nil
	}
	sizes, offsets := peakLayout(n)

	// Locate home peak.
	home := -1
	for k := range sizes {
		if idx >= offsets[k] && idx < offsets[k]+sizes[k] {
			home = k
			break
		}
	}
	if home < 0 {
		return nil
	}

	var sibs [][32]byte

	// (1) Bottom-up Merkle path inside the home peak.
	peakLeaves := t.mmr.leaves[offsets[home] : offsets[home]+sizes[home]]
	local := idx - offsets[home]
	level := make([][32]byte, len(peakLeaves))
	copy(level, peakLeaves)
	pos := local
	for len(level) > 1 {
		sib := pos ^ 1
		sibs = append(sibs, level[sib])
		// Build next level (left-to-right keccak256 pairing — buildTree order).
		next := make([][32]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, hashPair(level[i], level[i+1]))
		}
		level = next
		pos /= 2
	}

	// Compute every peak root once.
	peakRoots := make([][32]byte, len(sizes))
	for k := range sizes {
		peakRoots[k] = buildTree(t.mmr.leaves[offsets[k] : offsets[k]+sizes[k]])
	}

	// (2) Peaks to the right of home, folded right-to-left into one hash that
	// sits on the home peak's right.
	if home < len(sizes)-1 {
		acc := peakRoots[len(sizes)-1]
		for i := len(sizes) - 2; i > home; i-- {
			acc = hashPair(peakRoots[i], acc)
		}
		sibs = append(sibs, acc)
	}

	// (3) Peaks to the left of home, nearest-left first (right-to-left fold
	// order), each on the running root's left.
	for i := home - 1; i >= 0; i-- {
		sibs = append(sibs, peakRoots[i])
	}

	return sibs
}

// hashPair returns keccak256(left || right), the single combine primitive used
// throughout agnt2_mmr.go (buildTree:66-70 and getRoot:49-52).
func hashPair(left, right [32]byte) [32]byte {
	var combined [64]byte
	copy(combined[0:32], left[:])
	copy(combined[32:64], right[:])
	var out [32]byte
	copy(out[:], crypto.Keccak256(combined[:]))
	return out
}

// recomputeRoot rebuilds the MMR root from (leafHash, siblings, leafIndex)
// using only the leaf count n to recover sibling sides — the inverse of
// siblingsForIndex. A verifier with the leaf, its index, the proof siblings,
// and n can confirm the result equals getRoot() without the full leaf set.
func recomputeRoot(leafHash [32]byte, siblings [][32]byte, leafIndex, n uint64) [32]byte {
	if n == 0 {
		var zero [32]byte
		copy(zero[:], crypto.Keccak256([]byte{}))
		return zero
	}
	sizes, offsets := peakLayout(n)

	home := -1
	for k := range sizes {
		if leafIndex >= offsets[k] && leafIndex < offsets[k]+sizes[k] {
			home = k
			break
		}
	}
	if home < 0 {
		return [32]byte{}
	}

	si := 0
	acc := leafHash

	// (1) Climb the home peak. At each level the sibling is on the right iff
	// the current position is even (left child).
	homeSize := sizes[home]
	pos := leafIndex - offsets[home]
	for span := uint64(1); span < homeSize; span *= 2 {
		if si >= len(siblings) {
			return [32]byte{}
		}
		sib := siblings[si]
		si++
		if pos%2 == 0 {
			acc = hashPair(acc, sib) // sibling on the right
		} else {
			acc = hashPair(sib, acc) // sibling on the left
		}
		pos /= 2
	}

	// (2) Fold the right-peaks accumulator (sits on the right) if home is not
	// the rightmost peak.
	if home < len(sizes)-1 {
		if si >= len(siblings) {
			return [32]byte{}
		}
		acc = hashPair(acc, siblings[si])
		si++
	}

	// (3) Fold left peaks, nearest-left first, each on the left.
	for i := home - 1; i >= 0; i-- {
		if si >= len(siblings) {
			return [32]byte{}
		}
		acc = hashPair(siblings[si], acc)
		si++
	}

	return acc
}

// VerifyInclusion recomputes the root from the proof and reports whether it
// equals the supplied expected root. n is the trie's leaf count.
func VerifyInclusion(proof InclusionProof, expectedRoot [32]byte, n uint64) bool {
	got := recomputeRoot(proof.LeafHash, proof.Siblings, proof.LeafIndex, n)
	return got == expectedRoot
}

// Serialize is the deterministic, host-stable byte encoding of trie state:
// an 8-byte big-endian leaf count followed by every 32-byte leaf hash in
// append order. Two independent builds of the same corpus serialize to
// byte-identical output regardless of process/host (no map iteration, no
// pointers, no padding). The keys map is NOT serialized — it is fully
// reconstructible from the leaves + workflow metadata and would introduce
// nondeterministic map ordering.
func (t *agnt2Trie) Serialize() []byte {
	out := make([]byte, 0, 8+32*len(t.mmr.leaves))
	n := uint64(len(t.mmr.leaves))
	for i := 7; i >= 0; i-- {
		out = append(out, byte(n>>(uint(i)*8)))
	}
	for _, l := range t.mmr.leaves {
		out = append(out, l[:]...)
	}
	return out
}
