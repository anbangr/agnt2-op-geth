package vm

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// agnt2_trie_bench_test.go — WS3 per-typed-step execution-budget microbench.
//
// BenchmarkAgnt2TypedStep measures, for each (active_interactions ×
// compose_depth) cell, the cost of the four typed-step ops the precompile +
// trie wrapper perform:
//
//   - trie_update          one typed-state update (Append: interactionKey +
//                          leaf into the embedded MMR) — the production hot path
//   - inclusion_proof_build Prove(key): build the inclusion witness for one
//                          previously appended typed leaf
//   - inclusion_proof_verify VerifyInclusion: recompute the root from a witness
//   - typed_validation     validateAndBuildMMR over a compose_depth-step call —
//                          the full production typed-transition validation
//                          (per-leaf binding+chain check + trie append + root)
//
// Sub-benchmark names encode the cell so the percentile harness
// (benchmarks/scripts/run-ws3-budget.sh) can parse:
//
//	BenchmarkAgnt2TypedStep/ai1000_d1/trie_update-10   <iters>   <ns/op> ...
//
// active interactions sweep: {1000, 10000, 100000}; compose depth: {1,3,7}.
// makeChainedLeaves (agnt2_interaction_test.go) is the workload generator.
//
// Note on 100K: per AGNT2MaxStepsPerCall=4500, a single call cannot carry 100K
// leaves. The "active interactions" axis is the ACCUMULATED trie state (the
// standing set of live interactions), not one oversized call — the trie is
// pre-loaded to N leaves, and each measured op acts on that standing state
// (trie_update/proof) or runs one compose_depth-sized call against it
// (typed_validation). This matches the spec: the sweep spans accumulated state,
// not one call above the cap.

// benchActiveInteractions is the standing-trie size sweep.
var benchActiveInteractions = []int{1000, 10000, 100000}

// benchComposeDepths is the per-call typed-step fan-out sweep.
var benchComposeDepths = []int{1, 3, 7}

// composeCalldata builds valid precompile calldata for a depth-step compose
// call: version + stepCount + ABI(workflow_id) + depth chained leaves.
func composeCalldata(wfID string, depth int) []byte {
	wfHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(wfHash, depth)
	return makeInputWithLeaves(wfID, leaves)
}

func BenchmarkAgnt2TypedStep(b *testing.B) {
	for _, ai := range benchActiveInteractions {
		for _, depth := range benchComposeDepths {
			cellName := fmt.Sprintf("ai%d_d%d", ai, depth)
			b.Run(cellName, func(b *testing.B) {
				benchCell(b, ai, depth)
			})
		}
	}
}

func benchCell(b *testing.B, activeInteractions, depth int) {
	wfID := "ws3-budget-workflow"
	wfHash := crypto.Keccak256([]byte(wfID))
	var wf32 [32]byte
	copy(wf32[:], wfHash)

	// Pre-load the standing trie to `activeInteractions` leaves (the live set).
	preHashes := leafHashesFromChain(wfHash, activeInteractions)

	// --- trie_update: one Append against the standing trie -------------------
	// Each op appends one typed step; depth ops are appended per b.N batch so
	// the cell's compose_depth axis is exercised. We rebuild the standing trie
	// once per benchmark (outside the timed loop) and time only Append.
	b.Run("trie_update", func(b *testing.B) {
		base := newAgnt2Trie()
		for i := 0; i < activeInteractions; i++ {
			base.Append(interactionKey(wf32, uint32(i)), preHashes[i])
		}
		// A fresh leaf hash to append each iteration (depth folded per op).
		var newLeaf [32]byte
		copy(newLeaf[:], crypto.Keccak256([]byte("ws3-new-leaf")))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for d := 0; d < depth; d++ {
				base.Append(interactionKey(wf32, uint32(activeInteractions+i*depth+d)), newLeaf)
			}
		}
	})

	// --- inclusion_proof_build: Prove(key) for a standing leaf ---------------
	b.Run("inclusion_proof_build", func(b *testing.B) {
		t := newAgnt2Trie()
		for i := 0; i < activeInteractions; i++ {
			t.Append(interactionKey(wf32, uint32(i)), preHashes[i])
		}
		// Probe keys spread across the standing set (depth of them per op).
		probes := make([][32]byte, depth)
		for d := 0; d < depth; d++ {
			idx := (d * activeInteractions) / depth
			probes[d] = interactionKey(wf32, uint32(idx))
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for d := 0; d < depth; d++ {
				if _, ok := t.Prove(probes[d]); !ok {
					b.Fatalf("Prove failed for probe %d", d)
				}
			}
		}
	})

	// --- inclusion_proof_verify: recompute root from a witness ---------------
	b.Run("inclusion_proof_verify", func(b *testing.B) {
		t := newAgnt2Trie()
		for i := 0; i < activeInteractions; i++ {
			t.Append(interactionKey(wf32, uint32(i)), preHashes[i])
		}
		root := t.Root()
		n := t.LeafCount()
		proofs := make([]InclusionProof, depth)
		for d := 0; d < depth; d++ {
			idx := (d * activeInteractions) / depth
			p, ok := t.Prove(interactionKey(wf32, uint32(idx)))
			if !ok {
				b.Fatalf("Prove failed building verify fixture %d", d)
			}
			proofs[d] = p
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for d := 0; d < depth; d++ {
				if !VerifyInclusion(proofs[d], root, n) {
					b.Fatalf("VerifyInclusion failed for proof %d", d)
				}
			}
		}
	})

	// --- typed_validation: full validateAndBuildMMR over a depth-step call ----
	b.Run("typed_validation", func(b *testing.B) {
		input := composeCalldata(wfID, depth)
		stepCount := uint64(binary.BigEndian.Uint32(input[1:5]))
		wfParsed, abiHeaderSize, errCode := parseWorkflowID(input)
		if errCode != 0 {
			b.Fatalf("parseWorkflowID errCode 0x%02x", errCode)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, ec := validateAndBuildMMR(input, stepCount, abiHeaderSize, wfParsed)
			if ec != 0 {
				b.Fatalf("validateAndBuildMMR errCode 0x%02x", ec)
			}
		}
	})
}
