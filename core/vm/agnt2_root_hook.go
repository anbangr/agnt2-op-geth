package vm

// Week 11 Phase 7 — the package-level globalAgnt2RootStore singleton from
// the Week 10 scaffold has been removed. The canonical AGNT2 interaction
// MMR root is now derived from receipts via core/types.FoldInteractionRoot
// and committed in the block header (Header.InteractionRoot +
// Header.InteractionCount, both rlp:"optional", fork-gated by Optimism
// Isthmus). Block import recomputes the fold and rejects any header whose
// sequencer-set values disagree with the receipt-derived values.
//
// Why removed: the singleton was not block-safe under parallel block
// validation (parallel txpool simulation could publish block B's root
// before block A's consumer read it). The receipts-trie + block-header
// pattern is consensus-deterministic without per-block context, because
// the receipts already carry the per-leaf logs that fold to the same
// root deterministically.
//
// What replaced it:
//   - core/vm/agnt2_emit.go        — per-leaf log emission via stateDB.AddLog
//   - core/types/agnt2_header.go   — FoldInteractionRoot(receipts) → (root, count)
//   - core/block_validator.go      — header validation against the fold
//   - consensus/beacon/consensus.go — sequencer-side header population
//
// op-node consumers that previously called vm.GetInteractionRoot() now
// read header.InteractionRoot directly from the freshly-built block.
