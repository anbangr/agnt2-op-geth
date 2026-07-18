package types

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Independent reference fold (A4). Deliberately structured differently from the
// production foldMMR (recursive largest-power-of-2-prefix peak split + iterative
// perfect-tree build, vs production's bit-iteration + recursive tree), so a bug
// in one is caught by disagreement with the other. Both follow the same spec:
// perfect subtrees keccak(l||r); peaks largest-first; bag right-to-left.
func refPerfectTree(nodes [][32]byte) [32]byte {
	for len(nodes) > 1 {
		next := make([][32]byte, 0, len(nodes)/2)
		for i := 0; i < len(nodes); i += 2 {
			var h [32]byte
			copy(h[:], crypto.Keccak256(nodes[i][:], nodes[i+1][:]))
			next = append(next, h)
		}
		nodes = next
	}
	return nodes[0]
}

func refFoldMMR(leaves [][32]byte) common.Hash {
	if len(leaves) == 0 {
		return crypto.Keccak256Hash([]byte{})
	}
	var peaks [][32]byte
	rest := leaves
	for len(rest) > 0 {
		p := 1
		for p*2 <= len(rest) {
			p *= 2
		}
		peaks = append(peaks, refPerfectTree(rest[:p]))
		rest = rest[p:]
	}
	root := peaks[len(peaks)-1]
	for i := len(peaks) - 2; i >= 0; i-- {
		root = crypto.Keccak256Hash(peaks[i][:], root[:])
	}
	return root
}

// FuzzFoldMMR fuzzes the shared MMR fold over random leaf SEQUENCES (order
// matters; duplicates allowed) and asserts: determinism, agreement with the
// independent reference, single-leaf identity, and empty == keccak256("").
func FuzzFoldMMR(f *testing.F) {
	f.Add([]byte{}, uint8(0), uint8(1))
	f.Add([]byte("agnt2"), uint8(3), uint8(1))
	f.Add([]byte("multi-peak"), uint8(7), uint8(3))
	f.Add(bytes.Repeat([]byte{0xff}, 40), uint8(16), uint8(4))

	f.Fuzz(func(t *testing.T, seed []byte, nRaw uint8, dupMod uint8) {
		n := int(nRaw) % 65 // 0..64 leaves
		distinct := int(dupMod)%8 + 1
		leaves := make([][32]byte, n)
		for i := 0; i < n; i++ {
			// leaf i derived from seed + (i mod distinct): smaller `distinct`
			// -> more duplicate leaves in the sequence (exercises dup handling).
			leaves[i] = crypto.Keccak256Hash(seed, []byte{byte(i % distinct)})
		}

		got := foldMMR(leaves)

		// determinism
		if got != foldMMR(leaves) {
			t.Fatalf("foldMMR non-deterministic at n=%d", n)
		}
		// differential vs the independent reference
		if got != refFoldMMR(leaves) {
			t.Fatalf("foldMMR %s != independent ref %s (n=%d, distinct=%d)",
				got.Hex(), refFoldMMR(leaves).Hex(), n, distinct)
		}
		// empty and single-leaf edge cases
		if n == 0 && got != crypto.Keccak256Hash([]byte{}) {
			t.Fatalf("empty fold != keccak256(\"\"): %s", got.Hex())
		}
		if n == 1 {
			var want common.Hash
			copy(want[:], leaves[0][:])
			if got != want {
				t.Fatalf("single-leaf fold not identity: %s != %s", got.Hex(), want.Hex())
			}
		}
	})
}
