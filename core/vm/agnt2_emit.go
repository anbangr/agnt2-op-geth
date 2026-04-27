package vm

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
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
// Week 11 Phase 6: events are no longer stored in a singleton. The EVM
// dispatcher (evmAGNT2PostHook) re-parses calldata after a successful Run()
// and emits one types.Log per LeafEvent via stateDB.AddLog — receipt logs
// participate in the EVM journal (parent-frame REVERT drops them) and are
// observable via eth_getLogs.
type LeafEvent struct {
	WorkflowIDHash [32]byte // leaf bytes [0..32)   — keccak256(workflow_id)
	StepIndex      uint32   // zero-based; matches calldata leaf position
	StepIDHash     [32]byte // leaf bytes [32..64)  — keccak256(step_id)
	AgentRoleHash  [32]byte // leaf bytes [64..96)  — keccak256(agent_role)
	Payout         [32]byte // leaf bytes [96..128) — uint256 BE
	LeafHash       [32]byte // keccak256 of the 160-byte leaf body
}

// agnt2LeafEventSig is the canonical event signature consumed by off-chain
// indexers. The first topic of every emitted log is keccak256 of this string;
// renaming or reordering parameters is a breaking change.
const agnt2LeafEventSig = "AGNT2LeafEvent(bytes32,uint32,bytes32,bytes32,bytes32,bytes32)"

// agnt2LeafEventTopic0 is the topic[0] hash that uniquely identifies an
// AGNT2 leaf-event log. Computed once at package init via crypto.Keccak256
// over agnt2LeafEventSig — eth_getLogs filters on this exact value.
var agnt2LeafEventTopic0 = func() common.Hash {
	var h common.Hash
	copy(h[:], crypto.Keccak256([]byte(agnt2LeafEventSig)))
	return h
}()

// agnt2EmitLogs re-parses the AGNT2 precompile calldata and emits one
// types.Log per leaf via stateDB.AddLog. Called by the per-call-mode EVM
// dispatcher (evmAGNT2PostHook) only on the success path, so failed calls
// produce zero logs (matches the EVM journal model: a reverted call's logs
// are dropped).
//
// Why re-parse rather than thread events through Run()? Because Run() is
// signature-locked (PrecompiledContract.Run(input)) and giving it StateDB
// access would either require an upstream-incompatible signature change or
// a per-precompile thread-local — both fragile. Re-parsing in the
// dispatcher is consensus-deterministic (same parser, same input) and adds
// no signature surface to the precompile interface.
//
// Topic layout (locked at Phase 6):
//
//	topic[0] = keccak256("AGNT2LeafEvent(bytes32,uint32,bytes32,bytes32,bytes32,bytes32)")
//	topic[1] = WorkflowIDHash (indexed — eth_getLogs filterable)
//
// Data layout (5 × 32 = 160 bytes):
//
//	[ 0..32)  StepIndex (uint32 left-padded to 32 bytes)
//	[32..64)  StepIDHash
//	[64..96)  AgentRoleHash
//	[96..128) Payout
//	[128..160) LeafHash
//
// Gas accounting: caller (RequiredGas) bills LogGas + 2*LogTopicGas + 160*LogDataGas
// per leaf up-front so the dispatcher's emit loop does NOT bill again.
func agnt2EmitLogs(stateDB StateDB, addr common.Address, input []byte) {
	if stateDB == nil {
		// Pre-Amsterdam EVM rules pass nil stateDB to RunPrecompiledContract;
		// without a stateDB we cannot AddLog. Phase 6 expects post-Amsterdam
		// (Optimism Isthmus / Jovian wires nil stateDB only when the EVM is
		// not in Amsterdam mode — AGNT2 chains are Amsterdam+). Defensive
		// no-op preserves existing dispatch tests that pass nil.
		return
	}
	_, events, errCode := agnt2ParseLeaves(input)
	if errCode != 0 {
		// Defensive: dispatcher already verified Run succeeded before calling
		// us. A non-zero errCode here means parser non-determinism (a
		// consensus bug). Skip emission — the precompile result is already
		// the user-visible outcome; a panic here would crash the node.
		return
	}
	for _, e := range events {
		var stepIndexWord [32]byte
		binary.BigEndian.PutUint32(stepIndexWord[28:32], e.StepIndex)

		data := make([]byte, 0, 160)
		data = append(data, stepIndexWord[:]...)
		data = append(data, e.StepIDHash[:]...)
		data = append(data, e.AgentRoleHash[:]...)
		data = append(data, e.Payout[:]...)
		data = append(data, e.LeafHash[:]...)

		stateDB.AddLog(&types.Log{
			Address: addr,
			Topics: []common.Hash{
				agnt2LeafEventTopic0,
				common.BytesToHash(e.WorkflowIDHash[:]),
			},
			Data: data,
		})
	}
}
