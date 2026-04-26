package vm

import (
	"github.com/ethereum/go-ethereum/crypto"
)

// agnt2MMR is a minimal in-memory Merkle Mountain Range mirroring the off-chain
// reference in benchmarks/src/trace.ts. It accumulates leaf hashes and computes
// the root via right-to-left peak combining. Used by the AGNT2 interaction
// precompile (agnt2_interaction.go) to validate that workflow leaves submitted
// in calldata produce a root the off-chain verifier can match.
//
// "Shadow-copy" semantics: this MMR is built fresh per Run() invocation. It
// computes the root for the leaves in the current call but does NOT persist
// state across blocks — that's Week 11 scope (real trie storage).
type agnt2MMR struct {
	leaves [][32]byte
}

// append adds a leaf hash to the MMR.
func (m *agnt2MMR) append(leafHash [32]byte) {
	m.leaves = append(m.leaves, leafHash)
}

// getRoot computes the MMR root. Empty MMR returns keccak256("").
func (m *agnt2MMR) getRoot() [32]byte {
	n := uint64(len(m.leaves))
	if n == 0 {
		var zero [32]byte
		copy(zero[:], crypto.Keccak256([]byte{}))
		return zero
	}

	// Bit-decompose n into peaks (largest power-of-2 first).
	var peaks [][32]byte
	var offset uint64 = 0
	for bit := 31; bit >= 0; bit-- {
		size := uint64(1) << uint(bit)
		if n&size != 0 {
			peak := buildTree(m.leaves[offset : offset+size])
			peaks = append(peaks, peak)
			offset += size
		}
	}

	// Fold peaks right-to-left.
	root := peaks[len(peaks)-1]
	for i := len(peaks) - 2; i >= 0; i-- {
		var combined [64]byte
		copy(combined[0:32], peaks[i][:])
		copy(combined[32:64], root[:])
		copy(root[:], crypto.Keccak256(combined[:]))
	}
	return root
}

// buildTree recursively pairs adjacent nodes via keccak256 until a single root
// remains. Input length must be a power of 2 (caller ensures this via the
// bit-decomposition in getRoot).
func buildTree(nodes [][32]byte) [32]byte {
	if len(nodes) == 1 {
		return nodes[0]
	}
	next := make([][32]byte, 0, len(nodes)/2)
	for i := 0; i < len(nodes); i += 2 {
		var combined [64]byte
		copy(combined[0:32], nodes[i][:])
		copy(combined[32:64], nodes[i+1][:])
		var hash [32]byte
		copy(hash[:], crypto.Keccak256(combined[:]))
		next = append(next, hash)
	}
	return buildTree(next)
}
