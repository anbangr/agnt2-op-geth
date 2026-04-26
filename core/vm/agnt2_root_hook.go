package vm

import (
	"sync"
)

// WARNING — Week 10 scaffold: NOT BLOCK-SAFE.
//
// This store holds only the most-recent root computed by Run(). It is
// thread-safe (sync.RWMutex) but NOT block-safe: parallel validation of
// blocks A and B can publish B's root before A's consumer reads it. The
// mutex prevents data races, not block confusion.
//
// Acceptable use cases for Week 10:
//   - Single-block integration tests (test/op-node integration with one
//     block per test).
//   - Sequential local devnet runs (op-node consumes the root immediately
//     after the precompile call within the same block proposal).
//
// FORBIDDEN use cases until Week 11:
//   - Production block validation under any concurrency.
//   - Any code that assumes "I just got a root" implies "the root for the
//     block I am validating" — those are NOT the same in this scaffold.
//
// Week 11 will replace this singleton with a per-block context-scoped
// store that binds the root to (blockNumber, txIndex) so parallel
// validation is safe.

// agnt2RootStore holds the most recent AGNT2 interaction MMR root computed
// by the precompile at 0x0BC2. This is a Week 10 scaffold of the native root
// output hook (ADR 002 §Week-10-Scope item 5) that op-node will eventually
// read to populate the L2 block header interaction root.
//
// Thread safety: the EVM may dispatch precompile calls concurrently across
// blocks (parallel block validation, parallel txpool simulation). The store
// uses sync.RWMutex so reads (op-node consumption) and writes (precompile
// success path) are race-safe.
//
// Persistent storage: this is in-memory only. Across-block state lives in the
// real op-geth trie (Week 11). For Week 10, the store mirrors only the most
// recent root for op-node integration testing.
type agnt2RootStore struct {
	mu   sync.RWMutex
	root [32]byte
	set  bool
}

func (s *agnt2RootStore) get() ([32]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.root, s.set
}

func (s *agnt2RootStore) put(root [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.root = root
	s.set = true
}

// globalAgnt2RootStore is the package-level singleton consumed by op-node.
// Unexported so external packages can no longer reassign or nil the singleton.
var globalAgnt2RootStore = &agnt2RootStore{}

// GetInteractionRoot returns the most recent AGNT2 MMR root and a "set" flag.
// If set is false, no precompile call has succeeded yet (block header should
// use the empty MMR root keccak256("") = 0xc5d24601...).
//
// Week 10 scope: returns the root from the most recent successful Run(). Week
// 11 will replace this with a per-block trie read.
//
// NOT block-safe; see WARNING at top of file.
func GetInteractionRoot() ([32]byte, bool) {
	return globalAgnt2RootStore.get()
}
