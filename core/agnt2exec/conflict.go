package agnt2exec

// Conflict-serialization model for the DAG-aware parallel scheduler (spine's scheduler
// half). Two typed ops may execute in parallel iff their DATA write-sets are disjoint.
//
// TWO-PHASE, on purpose. The per-block MMR folds (interaction / typed-op / re-exec
// roots + their counts) are a GLOBAL sequential append — every op bumps the same MMR
// head and count — so including them in the conflict set would serialize everything and
// leave zero parallelism. They are therefore excluded here and handled as a separate,
// cheap, deterministic COMMIT-order pass (a keccak per op; the executor's measurement
// showed the fold is a tiny fraction of the per-op cost, which is dominated by
// settlement state-writes). This layer models only the DATA keys — escrow, balances,
// reputation, the per-workflow leaf chain, TTL, and the re-exec ring — over which real
// parallelism exists.
//
// SOUNDNESS. The declared dependency edge set (parent_invoke_id: a RESPOND's InvokeRef
// AND an INVOKE's DepInvokeIds) is a SUBSET of the conflict edges: a dependent op READS
// ring slot ring:{parentTxHash}, which the parent INVOKE writes, so every declared edge
// is an RW conflict (spot-checked over a workload with both edge kinds by
// TestSchedule_DepsSubsetOfConflicts — a by-construction argument + a synthetic check,
// not a general proof). The conflict layer never DROPS a declared dependency.
//
// COMMUTATIVITY (the load-bearing modeling choice). Two ops that only both WRITE a
// COMMUTATIVE key (bal:{agent}, rep:{agent} — pure additive credit / reputation
// append) need NOT be ordered: the result is order-independent, so a commutativity-
// aware executor (per-worker deltas merged, or atomic add) can run them concurrently.
// A generic conflict-based executor (Block-STM) instead sees a write-write and
// serializes them. Conflicts models the commutativity-aware view (the DEFAULT); a WW
// on a commutative key is NOT a conflict, but any READ of that key (a barrier needing
// the aggregate) IS. ConflictsConservative models the generic Block-STM view (every
// shared write conflicts). The measurement reports BOTH — the gap is exactly the value
// of commutativity-awareness, and the naive "just serialize on write-write" collapse.

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// key namespaces (single byte, disjoint) over the typed-op keyspace.
const (
	nsEscrow byte = 'E' // escrow FSM slot per workflow      esc:{wf}
	nsBal    byte = 'B' // agent token balance               bal:{agent}
	nsRep    byte = 'R' // agent reputation counter          rep:{agent}
	nsLeaf   byte = 'L' // per-workflow interaction-leaf chain (prevLeafHash) leaf:{wf}
	nsTTL    byte = 'T' // per-workflow deadline entry        ttl:{wf}
	nsRing   byte = 'G' // re-exec ring slot per tx hash      ring:{txHash}
)

// Key is a namespaced, comparable data-conflict key (usable as a map key).
type Key struct {
	NS byte
	ID common.Hash
}

func kWF(ns byte, wf common.Hash) Key { return Key{ns, wf} }
func kAddr(ns byte, a common.Address) Key {
	return Key{ns, common.BytesToHash(a[:])}
}

// RWSet is one op's declared read / write footprint over the data keyspace.
type RWSet struct {
	Read  []Key
	Write []Key
}

// commutative reports whether write-write on a key need NOT be ordered (pure additive
// / append semantics): agent balance credit and reputation append.
func commutative(ns byte) bool { return ns == nsBal || ns == nsRep }

// DeclareRW returns the DATA read/write footprint of a typed op, statically derivable
// from its type + fields. The leaf:{wf} key models the DESIGN's per-workflow
// prevLeafHash chain (each step's interaction leaf reads the previous), which the
// current stub executor over-approximates (it writes distinct per-step slots and reads
// no prior leaf); the escrow/bal/rep/ring/ttl keys match what Executor.ComposedStep
// touches. Conservative in the safe direction (coarser leaf key can only add ordering).
//
// signer is needed to recover the sender agent; a bad signature yields an empty set
// (the op would be skipped by the fold anyway).
func DeclareRW(tx *types.Transaction, signer types.Signer) RWSet {
	switch tx.Type() {
	case types.InvokeTxType:
		opId, ok := tx.Agnt2OperationID()
		if !ok {
			return RWSet{}
		}
		// INVOKE writes its workflow's leaf chain + TTL entry, and (at block level) its
		// output into ring slot ring:{txHash} — the slot a dependent op reads.
		rw := RWSet{
			Write: []Key{kWF(nsLeaf, opId.WorkflowId), kWF(nsTTL, opId.WorkflowId), kWF(nsRing, tx.Hash())},
		}
		// An INVOKE may depend on prior INVOKEs (DepInvokeIds) whose committed outputs it
		// reads — the ring slots those parents wrote. Declaring these reads keeps every
		// declared dependency edge (not just RESPOND->InvokeRef) a real RW conflict.
		for _, dep := range tx.Agnt2Dependencies() {
			rw.Read = append(rw.Read, kWF(nsRing, dep))
		}
		return rw
	case types.RespondTxType:
		opId, ok := tx.Agnt2OperationID()
		if !ok {
			return RWSet{}
		}
		rw := RWSet{Write: []Key{kWF(nsLeaf, opId.WorkflowId), kWF(nsTTL, opId.WorkflowId)}}
		// RESPOND reads its parent INVOKE's ring slot — the RW conflict that makes the
		// parent_invoke_id edge a subset of the conflict relation.
		if deps := tx.Agnt2Dependencies(); len(deps) > 0 {
			rw.Read = append(rw.Read, kWF(nsRing, deps[0]))
		}
		return rw
	case types.ComposeTypedTxType:
		wf, ok := tx.Agnt2ComposeWorkflowId()
		if !ok {
			return RWSet{}
		}
		n := int(composeStepCount(tx))
		// COMPOSE settles the workflow escrow and credits balance + reputation to each
		// of its n agents. The per-agent keys are the CROSS-WORKFLOW conflict surface:
		// two COMPOSEs of DIFFERENT workflows sharing an agent collide here with no
		// parent edge — the exact serialization the topology model misses.
		rw := RWSet{Read: []Key{kWF(nsEscrow, wf)}, Write: []Key{kWF(nsEscrow, wf), kWF(nsLeaf, wf)}}
		for i := 0; i < n; i++ {
			ag := composeAgent(wf, i)
			rw.Write = append(rw.Write, kAddr(nsBal, ag), kAddr(nsRep, ag))
		}
		return rw
	default:
		return RWSet{}
	}
}

// Conflicts is the COMMUTATIVITY-AWARE relation: two ops conflict if they share a key
// under WR or RW, or under WW on a NON-commutative key. A write-write on a commutative
// key (bal:/rep:) does NOT conflict (order-independent additive credit). This is the
// default an AGNT2-aware executor targets.
func Conflicts(a, b RWSet) bool { return conflictsWith(a, b, false) }

// ConflictsConservative is the generic Block-STM relation: ANY shared key under
// WW/WR/RW conflicts, including commutative write-write. Models an executor with no
// commutativity knowledge.
func ConflictsConservative(a, b RWSet) bool { return conflictsWith(a, b, true) }

func conflictsWith(a, b RWSet, commutativeIsWW bool) bool {
	aw := keySet(a.Write)
	for _, k := range b.Write { // WW
		if aw[k] && (commutativeIsWW || !commutative(k.NS)) {
			return true
		}
	}
	for _, k := range b.Read { // WR: a writes k, b reads it (reader needs the aggregate)
		if aw[k] {
			return true
		}
	}
	bw := keySet(b.Write)
	for _, k := range a.Read { // RW
		if bw[k] {
			return true
		}
	}
	return false
}

func keySet(ks []Key) map[Key]bool {
	m := make(map[Key]bool, len(ks))
	for _, k := range ks {
		m[k] = true
	}
	return m
}
