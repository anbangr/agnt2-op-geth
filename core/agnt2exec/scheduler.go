package agnt2exec

// DAG-aware parallel scheduler (spine's scheduler half). Given a block of typed ops it
// produces a WAVE schedule: ops are partitioned into ordered waves such that every op
// in a wave is mutually conflict-free (disjoint data write-sets, per conflict.go), so a
// wave can execute in parallel, and waves run in order. The number of waves is the
// conflict critical-path (Span); the average wave size (Work/Span) is the realized
// parallelism — the honest ceiling on speedup this workload's TRUE conflicts allow.
//
// The point of the layer is the DELTA vs the topology-only (parent_invoke_id) schedule
// the sequencer-sim uses: TopologySchedule assumes ops with no declared parent edge are
// independent, so it over-counts parallelism; Schedule serializes cross-workflow
// settlements that share an agent (bal:/rep: conflicts). Comparing the two gives the
// 1000x claim its honest floor.

import (
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
)

// Schedule is a wave partition of a block's typed ops.
type Schedule struct {
	WaveOf []int   // WaveOf[i] = wave index of op i (0-based)
	Waves  [][]int // Waves[w] = op indices scheduled in wave w
	Work   int     // number of ops
	Span   int     // number of waves (conflict critical-path length)
	Width  int     // max ops in any single wave
}

// MaxParallelism is the realized parallelism = Work/Span: the average wave width in
// OP COUNT. It is the structural (unit-cost) upper bound; under heterogeneous op costs
// the cost-weighted speedup differs — use ParallelTimeModel for that. Nothing is
// actually executed in parallel here (no concurrent StateDB); this is the schedulable
// parallelism a perfectly-parallel executor could extract from the conflict structure.
func (s *Schedule) MaxParallelism() float64 {
	if s.Span == 0 {
		return 0
	}
	return float64(s.Work) / float64(s.Span)
}

// ParallelTimeModel returns (serial, parallel) wall-clock under the critical-path
// model: serial = sum of all op costs; parallel = sum over waves of the SLOWEST op in
// the wave (perfect intra-wave parallelism). This is the optimistic bound the conflict
// schedule permits — real execution is lower (StateDB contention, worker overhead).
func (s *Schedule) ParallelTimeModel(cost func(op int) time.Duration) (serial, parallel time.Duration) {
	for w := range s.Waves {
		var waveMax time.Duration
		for _, i := range s.Waves[w] {
			c := cost(i)
			serial += c
			if c > waveMax {
				waveMax = c
			}
		}
		parallel += waveMax
	}
	return serial, parallel
}

// BuildSchedule builds the COMMUTATIVITY-AWARE wave schedule: a write-write on a
// commutative key (bal:/rep:) does not force ordering (an AGNT2-aware executor merges
// those credits). This is the parallelism actually available to such an executor.
func BuildSchedule(txs []*types.Transaction, signer types.Signer) *Schedule {
	return buildSchedule(txs, signer, false)
}

// BuildScheduleConservative builds the generic Block-STM wave schedule: every shared
// write-write serializes, including commutative credits. This is what an executor with
// no commutativity knowledge gets — the naive collapse.
func BuildScheduleConservative(txs []*types.Transaction, signer types.Signer) *Schedule {
	return buildSchedule(txs, signer, true)
}

// buildSchedule is the shared wave list-scheduler. Deterministic: wave(op) = 1 + max
// wave over earlier CONFLICTING ops (0 if none), so same-wave ops never conflict and
// block order is the tiebreak. commutativeIsWW=true treats commutative write-write as
// ordering (conservative); false lets commutative writers share a wave.
func buildSchedule(txs []*types.Transaction, signer types.Signer, commutativeIsWW bool) *Schedule {
	rws := make([]RWSet, len(txs))
	for i, tx := range txs {
		rws[i] = DeclareRW(tx, signer)
	}
	lastW := map[Key]int{} // wave of the latest writer of a key
	lastR := map[Key]int{} // wave of the latest reader of a key
	wave := make([]int, len(txs))
	for i := range txs {
		m := -1
		for _, k := range rws[i].Write {
			// WW: only orders on non-commutative keys (or when treating commutative as WW).
			if commutativeIsWW || !commutative(k.NS) {
				if w, ok := lastW[k]; ok && w > m {
					m = w
				}
			}
			// WR: a write must follow any prior reader of the key.
			if r, ok := lastR[k]; ok && r > m {
				m = r
			}
		}
		for _, k := range rws[i].Read { // RW: a read must follow any prior writer.
			if w, ok := lastW[k]; ok && w > m {
				m = w
			}
		}
		wave[i] = m + 1
		// Every writer bumps lastW (so a future READER orders after it via RW even on a
		// commutative key); readers take the max.
		for _, k := range rws[i].Write {
			if w, ok := lastW[k]; !ok || wave[i] > w {
				lastW[k] = wave[i]
			}
		}
		for _, k := range rws[i].Read {
			if r, ok := lastR[k]; !ok || wave[i] > r {
				lastR[k] = wave[i]
			}
		}
	}
	return assemble(wave, len(txs))
}

// BuildTopologySchedule is the topology-only baseline the sequencer-sim uses: the only
// serialization edges are parent_invoke_id (a RESPOND after its parent INVOKE); ops
// with no declared parent — including every COMPOSE — are assumed independent. It
// therefore over-states parallelism whenever real write-sets conflict without a parent
// edge (the delta this whole layer exists to expose).
func BuildTopologySchedule(txs []*types.Transaction, signer types.Signer) *Schedule {
	idxOf := make(map[[32]byte]int, len(txs))
	for i, tx := range txs {
		idxOf[tx.Hash()] = i
	}
	wave := make([]int, len(txs))
	for i, tx := range txs {
		w := 0
		for _, dep := range tx.Agnt2Dependencies() {
			if j, ok := idxOf[dep]; ok && wave[j]+1 > w {
				w = wave[j] + 1
			}
		}
		wave[i] = w
	}
	return assemble(wave, len(txs))
}

func assemble(wave []int, n int) *Schedule {
	span := 0
	for _, w := range wave {
		if w+1 > span {
			span = w + 1
		}
	}
	waves := make([][]int, span)
	for i, w := range wave {
		waves[w] = append(waves[w], i)
	}
	width := 0
	for _, ws := range waves {
		if len(ws) > width {
			width = len(ws)
		}
	}
	return &Schedule{WaveOf: wave, Waves: waves, Work: n, Span: span, Width: width}
}

// WidthBoundedMakespan is the wave-barriered makespan of a wave partition on W identical
// workers: each conflict-free wave is list-scheduled (LPT) onto W workers and the whole
// schedule is the SUM of per-wave makespans (a hard barrier between waves, faithful to the
// wg.Wait() barrier in RunParallel). It is host-INDEPENDENT (pure arithmetic over the wave
// partition + the per-op cost model — no goroutines, no core count) and DETERMINISTIC, so
// applying the identical formula to two arms cancels any model bias in their RATIO.
//
// It is a STRICT GENERALIZATION of Schedule.ParallelTimeModel's `parallel`: W=1 collapses to
// the serial sum of all costs; W>=Schedule.Width recovers the unbounded-width `parallel`
// time (each wave's makespan is its slowest op). W=16 is the honest finite-width point in
// between (matching the forkjoin fan-out). LPT is within (4/3 - 1/(3W)) of optimal.
func WidthBoundedMakespan(waves [][]int, cost func(op int) time.Duration, W int) time.Duration {
	if W < 1 {
		W = 1
	}
	var total time.Duration
	for _, wave := range waves {
		if len(wave) == 0 {
			continue
		}
		costs := make([]time.Duration, len(wave))
		for i, op := range wave {
			costs[i] = cost(op)
		}
		total += lptMakespan(costs, W)
	}
	return total
}

// lptMakespan list-schedules `costs` onto W identical workers longest-processing-time-first
// (sort descending, assign each to the least-loaded worker) and returns the max worker load
// — the wave's makespan. Deterministic; O(k log k + k*W) for a k-op wave.
func lptMakespan(costs []time.Duration, W int) time.Duration {
	if W < 1 {
		W = 1
	}
	sorted := append([]time.Duration(nil), costs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] > sorted[j] })
	load := make([]time.Duration, W)
	for _, c := range sorted {
		mi := 0 // least-loaded worker
		for w := 1; w < W; w++ {
			if load[w] < load[mi] {
				mi = w
			}
		}
		load[mi] += c
	}
	var mx time.Duration
	for _, l := range load {
		if l > mx {
			mx = l
		}
	}
	return mx
}

// GrahamAreaBound is the per-wave area lower bracket Sum_waves max(maxOp_w, ceil(sum_w/W)):
// an auditable lower bound that the LPT makespan must sit at or above (LPT <= 4/3 * OPT), so
// a reviewer can bracket every reported width-bounded number without trusting the scheduler.
func GrahamAreaBound(waves [][]int, cost func(op int) time.Duration, W int) time.Duration {
	if W < 1 {
		W = 1
	}
	var total time.Duration
	for _, wave := range waves {
		if len(wave) == 0 {
			continue
		}
		var sum, mx time.Duration
		for _, op := range wave {
			c := cost(op)
			sum += c
			if c > mx {
				mx = c
			}
		}
		area := sum / time.Duration(W) // ceil(sum/W)
		if sum%time.Duration(W) != 0 {
			area++
		}
		if mx > area {
			total += mx
		} else {
			total += area
		}
	}
	return total
}
