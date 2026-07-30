package agnt2exec

// Measured parallel execution over a wave schedule. The scheduler (scheduler.go)
// produces the schedulable parallelism as a critical-path MODEL; this runs the
// composed step for real, with a bounded worker pool, and returns MEASURED wall-clock
// so the model can be checked against actual goroutine overhead + load imbalance at a
// finite worker count.
//
// HONEST SCOPE — this measures TIME, not a canonical end-state. Each worker holds its
// OWN StateDB (geth's StateDB is not concurrent-safe). Note the serial and parallel
// paths do IDENTICAL per-op work: ComposedStep reads the re-exec ring slot EMPTY in
// BOTH (the ring write is a block-level step, not part of ComposedStep, and per-op
// Snapshot/Revert resets state each iteration in serial too), so cross-op reads return
// zero regardless of path — the comparison is fair, only read VALUES differ, not the
// work or timing. A production parallel executor would additionally MERGE each wave's
// disjoint write-sets into a shared base between waves (a deterministic, cheap step this
// does not build — the same Block-STM-style gap the scheduler doc names).

import (
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
)

// StateFactory builds a fresh writable StateDB (e.g. an in-memory one for a bench).
type StateFactory func() vm.StateDB

// RunSerial executes every op in block order on a single StateDB and returns wall-clock.
func (e *Executor) RunSerial(txs []*types.Transaction, mkState StateFactory) time.Duration {
	sdb := mkState()
	e.EnsureSystemAccounts(sdb)
	start := time.Now()
	for _, tx := range txs {
		snap := sdb.Snapshot()
		_, _ = e.ComposedStep(sdb, tx)
		sdb.RevertToSnapshot(snap)
	}
	return time.Since(start)
}

// RunParallel executes the wave schedule with `workers` goroutines (each on its own
// StateDB), a barrier between waves, and returns the MEASURED wall-clock. Ops within a
// wave are conflict-free (by construction), so distributing them across workers is safe
// for timing; see the file header for the state-merge caveat.
func (e *Executor) RunParallel(txs []*types.Transaction, sched *Schedule, workers int, mkState StateFactory) time.Duration {
	if workers < 1 {
		workers = 1
	}
	states := make([]vm.StateDB, workers)
	for i := range states {
		states[i] = mkState()
		e.EnsureSystemAccounts(states[i])
	}
	start := time.Now()
	for _, wave := range sched.Waves {
		if len(wave) == 0 {
			continue
		}
		ch := make(chan int, len(wave))
		for _, op := range wave {
			ch <- op
		}
		close(ch)
		var wg sync.WaitGroup
		n := workers
		if n > len(wave) {
			n = len(wave)
		}
		for w := 0; w < n; w++ {
			wg.Add(1)
			go func(sdb vm.StateDB) {
				defer wg.Done()
				for op := range ch {
					snap := sdb.Snapshot()
					_, _ = e.ComposedStep(sdb, txs[op])
					sdb.RevertToSnapshot(snap)
				}
			}(states[w])
		}
		wg.Wait() // wave barrier
	}
	return time.Since(start)
}
