package agnt2exec

import (
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// E-A cost model (ns/op, MEASURED via BenchmarkComposedStep on this host, LOCKED — not
// interpolated). compose is fan-in 16 for the forkjoin-w16 workload. R (the AGNT2/baseline ratio)
// is LOAD-BEARING on these constants: heterogeneous greedy-LPT packing of the compose:invoke:respond
// ratio means they do NOT cancel in the ratio, so R is reported for THIS measured cost model.
const (
	eaInvokeNS  = 3699  // BenchmarkComposedStep/invoke
	eaRespondNS = 2524  // BenchmarkComposedStep/respond
	eaCompose16 = 50746 // BenchmarkComposedStep/compose_fanin_16
)

func eaCost(txs []*types.Transaction) func(op int) time.Duration {
	return func(op int) time.Duration {
		switch txs[op].Type() {
		case types.InvokeTxType:
			return eaInvokeNS * time.Nanosecond
		case types.RespondTxType:
			return eaRespondNS * time.Nanosecond
		case types.ComposeTypedTxType:
			return eaCompose16 * time.Nanosecond
		default:
			return 0
		}
	}
}

func eaSerial(txs []*types.Transaction, cost func(int) time.Duration) time.Duration {
	var s time.Duration
	for i := range txs {
		s += cost(i)
	}
	return s
}

func speedup(serial, makespan time.Duration) float64 {
	if makespan <= 0 {
		return 0
	}
	return float64(serial) / float64(makespan)
}

// TestMeasureWidthAwareBaseline emits the E-A fair-baseline artifact: at a BOUNDED worker
// width W it compares the AGNT2 declared-dependency (commutativity-aware) scheduler against a
// width-matched dependency-oblivious baseline (generic Block-STM conflict relation, GENEROUS —
// perfect static conflict oracle + zero abort/retry; both arms use the same greedy block-order
// wave coloring), with FIFO as a serial lower-bound sanity floor and the unbounded-width
// conservative model kept only as context. The money number is R = makespan_oblivious /
// makespan_AGNT2 = the value of static COMMUTATIVITY CLASSIFICATION (the one bit by which the arms
// differ). Honest headline: R = 1.0 ONLY at an effectively-unbounded agent pool (arms TIE); across
// the whole finite sweep AGNT2 WINS, growing monotonically as the pool concentrates. R depends on
// BOTH P and N (the ~N*fanIn collision surface) and reaches 1 only as P -> infinity — fanIn*W is
// NOT the crossover (at P=256, R is ~9.7x, not ~1). Run:
//
//	go test ./core/agnt2exec/ -run TestMeasureWidthAwareBaseline -v
func TestMeasureWidthAwareBaseline(t *testing.T) {
	cfg := params.OptimismTestConfig
	signer := types.MakeSigner(cfg, big.NewInt(1), 0)
	const fanIn = 16

	type cell struct {
		N                  int     `json:"n_workflows"`
		Ops                int     `json:"ops"`
		AgentPool          string  `json:"agent_pool"`
		Width              int     `json:"worker_width"`
		Headline           bool    `json:"headline"`
		Agnt2Speedup       float64 `json:"col1_agnt2_declared_dep"`
		ObliviousSpeedup   float64 `json:"col2_dependency_oblivious_widthaware"`
		ConservUnbounded   float64 `json:"col3_conservative_unbounded_context"`
		FifoSpeedup        float64 `json:"col4_fifo_lowerbound"`
		R                  float64 `json:"r_value_of_commutativity_exposure"`
		Agnt2Span          int     `json:"agnt2_span"`
		Agnt2Width         int     `json:"agnt2_max_wave_width"`
		OblivSpan          int     `json:"oblivious_span"`
		OblivWidth         int     `json:"oblivious_max_wave_width"`
		GrahamBracketAgnt2 float64 `json:"graham_bracket_speedup_agnt2"`
		GrahamBracketObliv float64 `json:"graham_bracket_speedup_oblivious"`
		FalseConflictEdges int     `json:"false_conflict_edges"`
	}

	saved := AgentPoolSize
	defer func() { AgentPoolSize = saved }()

	var cells []cell
	Ns := []int{50, 100, 200}
	pools := []uint64{1 << 40, 4096, 1024, 256, 64, 16}
	widths := []int{8, 16, 32}
	const headlineW = 16

	for _, N := range Ns {
		for _, pool := range pools {
			AgentPoolSize = pool
			txs := genWorkload(t, signer, fixedKey(t), cfg.ChainID, N, fanIn, false)
			cost := eaCost(txs)
			serial := eaSerial(txs, cost)

			schedAG := BuildSchedule(txs, signer)             // AGNT2 declared-dependency + commutativity-aware
			schedOB := BuildScheduleConservative(txs, signer) // dependency-oblivious (Block-STM conflict relation)
			_, conservParUnbounded := schedOB.ParallelTimeModel(cost)
			fce := FalseConflictEdges(txs, signer)

			label := "unbounded"
			if pool < (1 << 30) {
				label = itoa(pool)
			}
			for _, W := range widths {
				msAG := WidthBoundedMakespan(schedAG.Waves, cost, W)
				msOB := WidthBoundedMakespan(schedOB.Waves, cost, W)
				gbAG := GrahamAreaBound(schedAG.Waves, cost, W)
				gbOB := GrahamAreaBound(schedOB.Waves, cost, W)
				R := 0.0
				if msAG > 0 {
					R = float64(msOB) / float64(msAG)
				}
				cells = append(cells, cell{
					N: N, Ops: len(txs), AgentPool: label, Width: W, Headline: W == headlineW,
					Agnt2Speedup:     round2(speedup(serial, msAG)),
					ObliviousSpeedup: round2(speedup(serial, msOB)),
					ConservUnbounded: round2(speedup(serial, conservParUnbounded)),
					FifoSpeedup:      1.00,
					R:                round2(R),
					Agnt2Span:        schedAG.Span, Agnt2Width: schedAG.Width,
					OblivSpan: schedOB.Span, OblivWidth: schedOB.Width,
					GrahamBracketAgnt2: round2(speedup(serial, gbAG)),
					GrahamBracketObliv: round2(speedup(serial, gbOB)),
					FalseConflictEdges: fce,
				})
			}
		}
	}

	artifact := map[string]any{
		"schema": "agnt2-width-aware-baseline-v1",
		"workload": map[string]any{
			"shape":            "forkjoin-w16: N independent workflows, each INVOKE->RESPOND->COMPOSE(StepCount=16)",
			"n_workflows":      Ns,
			"fan_in":           fanIn,
			"agent_assignment": "UNIFORM over a pool of the stated SIZE (a skew/Zipf would concentrate conflicts and RAISE R, so uniform is the AGNT2-conservative choice)",
		},
		"cost_model_ns": map[string]any{
			"invoke": eaInvokeNS, "respond": eaRespondNS, "compose_fanin_16": eaCompose16,
			"provenance": "MEASURED via BenchmarkComposedStep on this host, LOCKED (compose fan-in 16 measured, not interpolated). LOAD-BEARING for R: heterogeneous LPT packing makes R depend on the compose:invoke:respond cost ratio -- both arms share the model but it does NOT cancel in the ratio, so R is reported for THIS measured cost model.",
		},
		"metric":         "WidthBoundedMakespan: wave-barriered greedy-LPT makespan on W identical workers, applied IDENTICALLY to both arms (host-independent, deterministic). speedup = serial/makespan(W). Strict generalization of the unbounded ParallelTimeModel (W=1 -> serial; W>=Width -> unbounded parallel). Both arms use the SAME greedy BLOCK-ORDER wave coloring (a list-scheduler, not an optimal-reorder executor).",
		"columns":        "col1 AGNT2 declared-dependency (commutativity-aware, BuildSchedule). col2 dependency-oblivious width-aware (BuildScheduleConservative -- clairvoyant perfect static conflict oracle, ZERO abort/retry, the same greedy block-order coloring; generous to the baseline). col1-vs-col2 is the FAIR head-to-head. col3 conservative UNBOUNDED-width (context only, the old critical-path number). col4 FIFO serial (1.00x lower-bound sanity, never a baseline).",
		"derived_R":      "R = makespan_oblivious/makespan_agnt2 = the value of static COMMUTATIVITY CLASSIFICATION (the ONE bit by which the arms differ). R depends on BOTH the agent pool P and the workflow count N (the ~N*fanIn settlement collision surface) and approaches 1 only as P -> infinity. fanIn*W is NOT the R->1 crossover -- see finding.",
		"headline_width": headlineW,
		"cells":          cells,
		"finding":        "R = 1.0 ONLY at an effectively-unbounded agent pool (the arms TIE). Across the ENTIRE finite agent-pool sweep AGNT2 WINS, monotonically growing as the population concentrates: at W=16, R = ~1.6x (P=4096), ~4.5x (P=1024), ~9.7x (P=256), ~13.8x (P=16) for N=200. AGNT2's own speedup is invariant to the pool (commutative merge keeps its span at the intra-workflow floor); the dependency-oblivious arm collapses because it FALSE-SERIALIZES the additive bal:/rep: settlement credits it cannot know commute. R depends on BOTH P and N (collision surface ~N*fanIn), so the R->1 crossover is far above 4096 and N-dependent -- it is NOT fanIn*W=256 (an earlier draft asserted a fanIn*W crossover; the cells refute it: at P=256 R is ~9.7x, not ~1). The advantage is REAL but CONDITIONAL on the production agent-access distribution, which is UNMEASURED. R isolates ONLY static commutativity classification of settlement credits (the one differing bit); the typed-dependency EXPOSURE (soundness / attributable failure / linear-time DAG construction) is a SEPARATE contribution both arms share and that R does NOT measure. FIFO is a 1.00x lower-bound sanity floor; the framing is a capability ladder FIFO <= dependency-oblivious Block-STM <= AGNT2, not a beat-FIFO headline.",
		"steelman":       "The baseline is GENEROUS to the dependency-oblivious side: a perfect static conflict oracle (no misprediction / discovery cost) and ZERO abort/re-execution -- more favorable than a real optimistic Block-STM, which would additionally abort + re-execute on the same bal:/rep: write-writes (a one-sided cost offered as the FalseConflictEdges sensitivity band, out of the headline). NOT a provable lower bound: both arms use the SAME greedy BLOCK-ORDER wave coloring (buildSchedule), a list-scheduler, NOT an optimal-reorder executor -- so R is the honest ratio against this width-matched greedy Block-STM, not against a hypothetical optimal-reorder one.",
		"honesty_boundaries": []string{
			"The AGNT2 advantage is CONDITIONAL on agent-pool concentration, which is UNMEASURED for production. R=1 (no win) only at an effectively-unbounded pool; R grows as the pool concentrates (fanIn*W=256 is NOT the crossover -- R is already ~9.7x at P=256). Diffuse-enough production agents shrink R toward 1.",
			"Uniform (not skewed) agent assignment (skew RAISES R, so uniform is AGNT2-conservative).",
			"Commutativity assumes NO op reads an aggregate balance/reputation (none here; such a read is a WR barrier that caps the AGNT2 arm too).",
			"Critical-path/makespan MODEL (not measured wall-clock). The wave barrier applies per-wave IDENTICALLY to both arms; the conservative arm's deeper span incurs more barriers -- part of the modeled cost of losing commutativity. A barrier-free global-DAG list-schedule is future work, NOT yet computed. A measured RunParallel@W row is a separate host-confounded validation.",
			"R is LOAD-BEARING on the measured cost model (heterogeneous LPT packing); it does NOT cancel in the ratio -- reported for the measured invoke/respond/compose_fanin_16 costs.",
			"leaf:{wf} is over-approximated (distinct per-step slots) identically in BOTH arms (safe direction, applies to both).",
		},
	}
	blob, _ := json.Marshal(artifact)
	t.Logf("ARTIFACT_JSON:%s", string(blob))
	// human-readable headline (W=16) sweep
	t.Logf("  --- headline W=%d (forkjoin-w16) ---", headlineW)
	for _, c := range cells {
		if c.Headline {
			t.Logf("  N=%-3d pool=%-9s agnt2=%-6.2f oblivious=%-6.2f R=%-6.2f (fifo=1.00, conserv_unbounded=%.2f) fce=%d",
				c.N, c.AgentPool, c.Agnt2Speedup, c.ObliviousSpeedup, c.R, c.ConservUnbounded, c.FalseConflictEdges)
		}
	}
}

// TestWidthMetric_GeneralizesModel proves WidthBoundedMakespan is a STRICT generalization of the
// committed unbounded-width ParallelTimeModel: W=1 recovers the serial sum, and W>=Width recovers
// the unbounded `parallel` time. So the new width-bounded number is the same model dialed to a
// finite worker count, not a different metric.
func TestWidthMetric_GeneralizesModel(t *testing.T) {
	cfg := params.OptimismTestConfig
	signer := types.MakeSigner(cfg, big.NewInt(1), 0)
	for _, pool := range []uint64{1 << 40, 64, 16} {
		AgentPoolSize = pool
		txs := genWorkload(t, signer, fixedKey(t), cfg.ChainID, 40, 16, false)
		cost := eaCost(txs)
		serial := eaSerial(txs, cost)
		for _, s := range []*Schedule{BuildSchedule(txs, signer), BuildScheduleConservative(txs, signer)} {
			if got := WidthBoundedMakespan(s.Waves, cost, 1); got != serial {
				t.Fatalf("W=1 must equal serial: got %v want %v (pool %d)", got, serial, pool)
			}
			_, parUnbounded := s.ParallelTimeModel(cost)
			if got := WidthBoundedMakespan(s.Waves, cost, s.Width); got != parUnbounded {
				t.Fatalf("W>=Width must equal unbounded parallel: got %v want %v (pool %d)", got, parUnbounded, pool)
			}
		}
	}
	AgentPoolSize = 1 << 40
}

// TestWidthBaseline_FairnessInvariants pins the fairness guardrails: in EVERY config
// (a) fifo <= oblivious <= agnt2 speedup (no column accidentally advantaged); (b) at an
// unbounded agent pool the AGNT2 and dependency-oblivious arms TIE (R==1.00 — a strawman
// baseline could never tie); (c) both arms have span>=3 (AGNT2 gets no intra-workflow free
// lunch — INVOKE->RESPOND->COMPOSE is serialized by non-commutative leaf:/esc: in both).
func TestWidthBaseline_FairnessInvariants(t *testing.T) {
	cfg := params.OptimismTestConfig
	signer := types.MakeSigner(cfg, big.NewInt(1), 0)
	defer func() { AgentPoolSize = 1 << 40 }()
	for _, N := range []int{50, 100, 200} {
		for _, pool := range []uint64{1 << 40, 4096, 1024, 256, 64, 16} {
			AgentPoolSize = pool
			txs := genWorkload(t, signer, fixedKey(t), cfg.ChainID, N, 16, false)
			cost := eaCost(txs)
			serial := eaSerial(txs, cost)
			schedAG := BuildSchedule(txs, signer)
			schedOB := BuildScheduleConservative(txs, signer)
			if schedAG.Span < 3 || schedOB.Span < 3 {
				t.Fatalf("span must be >=3 for both arms (intra-workflow chain): agnt2=%d oblivious=%d (N=%d pool=%d)", schedAG.Span, schedOB.Span, N, pool)
			}
			for _, W := range []int{8, 16, 32} {
				agnt2 := speedup(serial, WidthBoundedMakespan(schedAG.Waves, cost, W))
				obliv := speedup(serial, WidthBoundedMakespan(schedOB.Waves, cost, W))
				fifo := 1.00
				if !(fifo <= obliv+1e-9 && obliv <= agnt2+1e-9) {
					t.Fatalf("monotonicity violated fifo<=oblivious<=agnt2: %.3f %.3f %.3f (N=%d pool=%d W=%d)", fifo, obliv, agnt2, N, pool, W)
				}
				if pool == (1 << 40) {
					if r := obliv / agnt2; r < 0.999 || r > 1.001 {
						t.Fatalf("at unbounded pool arms must TIE (R~1): oblivious/agnt2=%.4f (N=%d W=%d)", r, N, W)
					}
				}
			}
		}
	}
}

// TestWidthBaseline_RGrowsWithConcentration PINS the money number so a regression that dropped the
// commutativity classification (making the AGNT2 arm identical to the dependency-oblivious one, i.e.
// R->1 everywhere) would be CAUGHT — the monotonicity + unbounded-tie guards alone SURVIVE that
// regression (identical arms are still monotone and still tie). It also asserts the honest shape: R=1
// only at an unbounded pool, growing strictly as the pool concentrates, and — refuting the retracted
// fanIn*W crossover — R at P=256 (=fanIn*W) is still a multi-x win, not ~1.
func TestWidthBaseline_RGrowsWithConcentration(t *testing.T) {
	cfg := params.OptimismTestConfig
	signer := types.MakeSigner(cfg, big.NewInt(1), 0)
	defer func() { AgentPoolSize = 1 << 40 }()
	const N, W = 100, 16
	R := func(pool uint64) float64 {
		AgentPoolSize = pool
		txs := genWorkload(t, signer, fixedKey(t), cfg.ChainID, N, 16, false)
		cost := eaCost(txs)
		ag := WidthBoundedMakespan(BuildSchedule(txs, signer).Waves, cost, W)
		ob := WidthBoundedMakespan(BuildScheduleConservative(txs, signer).Waves, cost, W)
		return float64(ob) / float64(ag)
	}
	rInf, r4096, r256, r16 := R(1<<40), R(4096), R(256), R(16)
	if rInf < 0.999 || rInf > 1.001 {
		t.Fatalf("R must be ~1.0 at an unbounded pool (arms tie), got %.3f", rInf)
	}
	if !(r4096 > rInf+0.1 && r256 > r4096+0.5 && r16 > r256+1.0) {
		t.Fatalf("R must grow strictly as the pool concentrates: inf=%.2f 4096=%.2f 256=%.2f 16=%.2f", rInf, r4096, r256, r16)
	}
	if r16 < 5.0 {
		t.Fatalf("R at pool=16 must be a large AGNT2 win (dropping commutativity would collapse this to ~1): got %.2f", r16)
	}
	if r256 < 3.0 {
		t.Fatalf("R at P=256 (=fanIn*W) must still be a multi-x win, NOT ~1 (refutes the retracted fanIn*W crossover): got %.2f", r256)
	}
}
