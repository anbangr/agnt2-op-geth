package miner

import (
	"context"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/internal/agnt2debug"
	"github.com/ethereum/go-ethereum/metrics"
)

// agnt2TypedTxDependencies is a package var so tests can exercise graph-only
// cycles without constructing tx-hash fixed points.
var agnt2TypedTxDependencies = func(tx *types.Transaction) []common.Hash {
	return tx.Agnt2Dependencies()
}

// commitTypedTransactions sorts typed txs topologically and commits them through the
// normal miner execution path.
func (miner *Miner) commitTypedTransactions(ctx context.Context, env *environment, txs []*types.Transaction) error {
	cycleCount := metrics.GetOrRegisterCounter("miner/typedTx/cycle", nil)
	missingDepCount := metrics.GetOrRegisterCounter("miner/typedTx/missingDep", nil)
	crossBlockCount := metrics.GetOrRegisterCounter("miner/typedTx/crossBlockResolved", nil)
	dupOpIdCount := metrics.GetOrRegisterCounter("miner/typedTx/duplicateOpId", nil)
	staleNonceCount := metrics.GetOrRegisterCounter("miner/typedTx/staleNonce", nil)
	malformedDepCount := metrics.GetOrRegisterCounter("miner/typedTx/malformedDep", nil)

	// Phase 1: reject stale nonces and deduplicate by logical op id, preserving insertion order.
	batchTxs := make(map[common.Hash]*types.Transaction)
	var batchOrder []common.Hash
	bySender := make(map[common.Address][]common.Hash)
	seenOpIds := make(map[types.Agnt2OperationID]common.Hash)

	for _, tx := range txs {
		from, err := types.Sender(env.signer, tx)
		if err == nil && env.state.GetNonce(from) > tx.Nonce() {
			staleNonceCount.Inc(1)
			continue
		}
		h := tx.Hash()
		if opId, ok := tx.Agnt2OperationID(); ok {
			if _, exists := seenOpIds[opId]; exists {
				dupOpIdCount.Inc(1)
				continue
			}
			seenOpIds[opId] = h
		}
		if _, exists := batchTxs[h]; exists {
			dupOpIdCount.Inc(1)
			continue
		}
		batchTxs[h] = tx
		batchOrder = append(batchOrder, h)
		if err == nil {
			bySender[from] = append(bySender[from], h)
		}
	}

	// Phase 2: build dependency graph (Kahn's) and identify deferred nodes.
	adj := make(map[common.Hash][]common.Hash) // dep → slice of dependents
	inDegree := make(map[common.Hash]int)
	deferred := make(map[common.Hash]struct{}) // InvokeTx nodes whose dep is not in batch
	type typedEdge struct {
		from common.Hash
		to   common.Hash
	}
	edges := make(map[typedEdge]struct{})
	addEdge := func(from, to common.Hash) {
		edge := typedEdge{from: from, to: to}
		if _, exists := edges[edge]; exists {
			return
		}
		edges[edge] = struct{}{}
		adj[from] = append(adj[from], to)
		inDegree[to]++
	}

	for _, h := range batchOrder {
		inDegree[h] = 0
	}

	for _, hashes := range bySender {
		sort.SliceStable(hashes, func(i, j int) bool {
			return batchTxs[hashes[i]].Nonce() < batchTxs[hashes[j]].Nonce()
		})
		for i := 1; i < len(hashes); i++ {
			addEdge(hashes[i-1], hashes[i])
		}
	}

	for _, h := range batchOrder {
		tx := batchTxs[h]
		for _, dep := range agnt2TypedTxDependencies(tx) {
			if depTx, exists := batchTxs[dep]; exists {
				// Intra-batch dependency. A typed-op dependency must reference an
				// INVOKE; a step naming a RESPOND or COMPOSE as its dependency is
				// malformed and is deferred (excluded from this block). This keeps
				// the honest builder from ever emitting a step → COMPOSE dependency
				// edge which, combined with the G1 same-workflow edge added below,
				// would form a Kahn cycle and evict the honest COMPOSE — a free,
				// permissionless settlement-liveness DoS (the griefer's step is a
				// cycle member, never committed, and pays no gas).
				if depTx.Type() != types.InvokeTxType {
					deferred[h] = struct{}{}
					malformedDepCount.Inc(1)
					continue
				}
				// Intra-batch dependency: add directed edge dep → h.
				addEdge(dep, h)
			} else {
				// Dependency not present in this batch.
				switch tx.Type() {
				case types.InvokeTxType:
					// InvokeTx with unresolved dep: defer to next block.
					deferred[h] = struct{}{}
					missingDepCount.Inc(1)
				case types.RespondTxType, types.ComposeTypedTxType:
					// Respond/Compose referencing a prior-block invoke: admit as cross-block resolved.
					crossBlockCount.Inc(1)
				}
			}
		}
	}

	// Any tx that depends on a deferred tx must also be deferred. Otherwise
	// unresolved dependency chains look like cycles after Kahn's sort.
	var deferredQueue []common.Hash
	for h := range deferred {
		deferredQueue = append(deferredQueue, h)
	}
	for len(deferredQueue) > 0 {
		curr := deferredQueue[0]
		deferredQueue = deferredQueue[1:]
		for _, neighbor := range adj[curr] {
			if _, exists := deferred[neighbor]; exists {
				continue
			}
			deferred[neighbor] = struct{}{}
			missingDepCount.Inc(1)
			deferredQueue = append(deferredQueue, neighbor)
		}
	}

	// Phase 2c (G1): same-workflow settlement ordering. Every in-batch admitted
	// INVOKE/RESPOND that shares a COMPOSE's WorkflowId is a constituent of that
	// workflow's settlement and must be committed before the COMPOSE. Add edge
	// step → compose so Kahn emits the COMPOSE after all its same-workflow steps.
	//
	// Placed AFTER deferred-propagation and skipping deferred steps: a deferred
	// step is not in the block, so it imposes no ordering requirement and must NOT
	// be able to drag the COMPOSE out of the block. This keeps the builder's
	// emitted order in agreement with the validator (which constrains a COMPOSE
	// only against same-workflow steps that are actually in-block) and prevents a
	// deferred same-workflow step from stalling settlement.
	stepsByWorkflow := make(map[common.Hash][]common.Hash)
	for _, h := range batchOrder {
		if _, isDeferred := deferred[h]; isDeferred {
			continue
		}
		if opId, ok := batchTxs[h].Agnt2OperationID(); ok { // INVOKE/RESPOND only
			stepsByWorkflow[opId.WorkflowId] = append(stepsByWorkflow[opId.WorkflowId], h)
		}
	}
	for _, h := range batchOrder {
		if _, isDeferred := deferred[h]; isDeferred {
			continue
		}
		wfID, ok := batchTxs[h].Agnt2ComposeWorkflowId()
		if !ok {
			continue
		}
		for _, stepHash := range stepsByWorkflow[wfID] {
			addEdge(stepHash, h) // constituent step → compose; lifts inDegree[compose] > 0
		}
	}

	// Phase 3: Kahn's BFS topological sort.
	// Seed the queue with nodes that have inDegree==0 and are not deferred.
	var queue []common.Hash
	for _, h := range batchOrder {
		if inDegree[h] == 0 {
			if _, isDeferred := deferred[h]; !isDeferred {
				queue = append(queue, h)
			}
		}
	}

	var sorted []*types.Transaction
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		sorted = append(sorted, batchTxs[curr])

		for _, neighbor := range adj[curr] {
			inDegree[neighbor]--
			if inDegree[neighbor] == 0 {
				if _, isDeferred := deferred[neighbor]; !isDeferred {
					queue = append(queue, neighbor)
				}
			}
		}
	}

	// Phase 4: any node with inDegree > 0 after Kahn's is part of a cycle.
	// Increment once per participating node.
	for _, h := range batchOrder {
		if _, isDeferred := deferred[h]; !isDeferred && inDegree[h] > 0 {
			cycleCount.Inc(1)
		}
	}

	// Phase 5: apply E4.6 bad-order injection if set for this block, then execute.
	if swapIdx, ok := agnt2debug.GetBadOrder(env.header.Number.Uint64()); ok && len(swapIdx) == 2 {
		i, j := swapIdx[0], swapIdx[1]
		if i >= 0 && j >= 0 && i < len(sorted) && j < len(sorted) {
			sorted[i], sorted[j] = sorted[j], sorted[i]
		} else {
			agnt2debug.SetBadOrder(env.header.Number.Uint64()+1, swapIdx)
		}
	}
	for _, tx := range sorted {
		env.state.SetTxContext(tx.Hash(), env.tcount)
		if err := miner.commitTransaction(ctx, env, tx); err != nil {
			return err
		}
	}

	return nil
}
