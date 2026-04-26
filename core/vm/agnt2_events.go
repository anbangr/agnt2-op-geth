package vm

import (
	"sync"
)

// LeafEvent represents a single COMPOSE step settlement emission. The
// off-chain replayer and the future fault-proof verifier consume this stream
// to reconstruct workflow state.
//
// Week 10 scaffold: events are appended to a per-call slice returned via
// LastEmittedEvents(). Week 11 will replace this with state.AddLog so the
// events are part of the EVM Log trie and survive across blocks. The event
// payload schema is locked here so the Week 11 transition is API-compatible.
type LeafEvent struct {
	WorkflowIDHash [32]byte // first 32 bytes of the leaf
	StepIndex      uint32   // zero-based; matches calldata leaf position
	LeafHash       [32]byte // keccak256 of the 160-byte leaf body
	Payout         [32]byte // bytes [96..128) of the leaf (uint256 BE)
}

// agnt2EventStore captures events from the most recent successful Run().
// Same WARNING as agnt2RootStore: NOT block-safe — only the most recent
// call's events are retained. Sequential single-block use only.
type agnt2EventStore struct {
	mu     sync.RWMutex
	events []LeafEvent
}

func (s *agnt2EventStore) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = s.events[:0]
}

func (s *agnt2EventStore) append(e LeafEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *agnt2EventStore) snapshot() []LeafEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]LeafEvent, len(s.events))
	copy(out, s.events)
	return out
}

var globalAgnt2EventStore = &agnt2EventStore{}

// LastEmittedEvents returns a snapshot of the events from the most recent
// successful precompile call. Week 10 scaffold; Week 11 replaces with
// EVM Log trie integration.
//
// NOT block-safe; see WARNING in agnt2_root_hook.go.
func LastEmittedEvents() []LeafEvent {
	return globalAgnt2EventStore.snapshot()
}
