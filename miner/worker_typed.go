package miner

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/internal/agnt2debug"
	"github.com/ethereum/go-ethereum/metrics"
)

// commitTypedTransactions sorts typed txs topologically and appends them to env.txs.
// Execution is deferred to the precompile layer; this function enforces ordering at the
// miner level (E4.3 prototype approach).
func (miner *Miner) commitTypedTransactions(ctx context.Context, env *environment, txs []*types.Transaction) error {
	_ = ctx // reserved for future cancellation propagation

	cycleCount := metrics.GetOrRegisterCounter("miner/typedTx/cycle", nil)
	missingDepCount := metrics.GetOrRegisterCounter("miner/typedTx/missingDep", nil)
	crossBlockCount := metrics.GetOrRegisterCounter("miner/typedTx/crossBlockResolved", nil)
	dupOpIdCount := metrics.GetOrRegisterCounter("miner/typedTx/duplicateOpId", nil)
	staleNonceCount := metrics.GetOrRegisterCounter("miner/typedTx/staleNonce", nil)
	_ = staleNonceCount // not incremented in E4.3 prototype (no commitTransaction call)

	// Phase 1: deduplicate by tx hash, preserving insertion order.
	batchTxs := make(map[common.Hash]*types.Transaction)
	var batchOrder []common.Hash

	for _, tx := range txs {
		h := tx.Hash()
		if _, exists := batchTxs[h]; exists {
			dupOpIdCount.Inc(1)
			continue
		}
		batchTxs[h] = tx
		batchOrder = append(batchOrder, h)
	}

	// Phase 2: build dependency graph (Kahn's) and identify deferred nodes.
	adj := make(map[common.Hash][]common.Hash) // dep → slice of dependents
	inDegree := make(map[common.Hash]int)
	deferred := make(map[common.Hash]struct{}) // InvokeTx nodes whose dep is not in batch

	for _, h := range batchOrder {
		inDegree[h] = 0
	}

	for _, h := range batchOrder {
		tx := batchTxs[h]
		for _, dep := range tx.Agnt2Dependencies() {
			if _, exists := batchTxs[dep]; exists {
				// Intra-batch dependency: add directed edge dep → h.
				adj[dep] = append(adj[dep], h)
				inDegree[h]++
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
		if inDegree[h] > 0 {
			cycleCount.Inc(1)
		}
	}

	// Phase 5: apply E4.6 bad-order injection if set for this block, then append.
	// Actual execution is handled by the precompile in a later phase.
	if swapIdx, ok := agnt2debug.GetBadOrder(env.header.Number.Uint64()); ok && len(swapIdx) == 2 {
		i, j := swapIdx[0], swapIdx[1]
		if i >= 0 && j >= 0 && i < len(sorted) && j < len(sorted) {
			sorted[i], sorted[j] = sorted[j], sorted[i]
		}
	}
	env.txs = append(env.txs, sorted...)

	return nil
}
