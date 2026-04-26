package vm

import (
	"sync"
)

// LeafEvent represents a single COMPOSE step settlement emission. The
// off-chain replayer and the future fault-proof verifier consume this stream
// to reconstruct workflow state.
//
// Schema mirrors the canonical 160-byte leaf body so verifiers can rebuild
// each leaf from the event alone. StepIndex is the zero-based call-relative
// position (the leaf's position in the calldata); prevLeafHash is omitted
// because it is reconstructible by hashing the previous event's leaf body.
//
// Week 10 scaffold: events are committed to the singleton store on
// successful Run() (commit-on-success, matching journaled state.AddLog
// semantics). Week 11 will replace this with state.AddLog so the events
// are part of the EVM Log trie and survive across blocks. The event payload
// schema is locked here so the Week 11 transition is API-compatible.
type LeafEvent struct {
	WorkflowIDHash [32]byte // leaf bytes [0..32)   — keccak256(workflow_id)
	StepIndex      uint32   // zero-based; matches calldata leaf position
	StepIDHash     [32]byte // leaf bytes [32..64)  — keccak256(step_id)
	AgentRoleHash  [32]byte // leaf bytes [64..96)  — keccak256(agent_role)
	Payout         [32]byte // leaf bytes [96..128) — uint256 BE
	LeafHash       [32]byte // keccak256 of the 160-byte leaf body
}

// agnt2EventStore captures events from the most recent successful Run().
// Same WARNING as agnt2RootStore: NOT block-safe — only the most recent
// successful call's events are retained. Sequential single-block use only.
type agnt2EventStore struct {
	mu     sync.RWMutex
	events []LeafEvent
}

// commit replaces the stored events with the supplied set in a single
// critical section. Called only after Run() proves the call succeeded, so
// failed runs leave the prior successful events untouched (mirroring EVM
// log journal rollback: a reverted tx's logs are dropped, prior tx logs
// remain visible to subsequent reads).
func (s *agnt2EventStore) commit(events []LeafEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events[:0], events...)
}

// reset is exported only for test isolation; production Run() never calls
// it. Required because globalAgnt2EventStore is package-level state and
// commit-on-success preserves prior events across calls.
func (s *agnt2EventStore) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = s.events[:0]
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
