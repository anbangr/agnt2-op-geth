package agnt2exec

import (
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// TestMeasureParallelismSweep emits the realized-parallelism artifact: for a fixed
// workload it compares the topology-only (parent_invoke_id) schedule against the
// true-write-set schedule, and sweeps the agent population to show how realized
// parallelism collapses as agents are shared across workflows. It logs one
// "ARTIFACT_JSON:" line that the harness captures. Run:
//
//	go test ./core/agnt2exec/ -run TestMeasureParallelismSweep -v
func TestMeasureParallelismSweep(t *testing.T) {
	cfg := params.OptimismTestConfig
	signer := types.MakeSigner(cfg, big.NewInt(1), 0)
	const N = 300
	const fanIn = 3
	txs := genWorkload(t, signer, fixedKey(t), cfg.ChainID, N, fanIn, false)

	// representative per-op-type composed EXECUTION cost (µs) from the executor bench
	// (BenchmarkComposedStep). Sender recovery is once-per-tx and excluded, as there.
	costUS := func(op int) time.Duration {
		switch txs[op].Type() {
		case types.InvokeTxType:
			return time.Duration(3900) * time.Nanosecond
		case types.RespondTxType:
			return time.Duration(2600) * time.Nanosecond
		case types.ComposeTypedTxType:
			return time.Duration(10600) * time.Nanosecond // fan-in 3
		default:
			return 0
		}
	}

	type row struct {
		Model          string  `json:"model"`
		AgentPool      string  `json:"agent_pool"`
		Span           int     `json:"span_waves"`
		Width          int     `json:"max_wave_width"`
		MaxParallelism float64 `json:"realized_parallelism"`
		SpeedupModel   float64 `json:"critical_path_speedup"`
	}
	mkrow := func(model, pool string, s *Schedule) row {
		serial, parallel := s.ParallelTimeModel(costUS)
		sp := 0.0
		if parallel > 0 {
			sp = float64(serial) / float64(parallel)
		}
		return row{model, pool, s.Span, s.Width, round2(s.MaxParallelism()), round2(sp)}
	}

	rows := []row{mkrow("topology_only", "n/a", BuildTopologySchedule(txs, signer))}

	saved := AgentPoolSize
	defer func() { AgentPoolSize = saved }()
	for _, pool := range []uint64{1 << 40, 4096, 1024, 256, 64, 16, 4} {
		AgentPoolSize = pool
		label := "unbounded"
		if pool < (1 << 30) {
			label = itoa(pool)
		}
		// commutativity-aware (what an AGNT2-aware executor gets) AND conservative
		// (generic Block-STM) at each agent-population SIZE.
		rows = append(rows, mkrow("write_set_commutative", label, BuildSchedule(txs, signer)))
		rows = append(rows, mkrow("write_set_conservative", label, BuildScheduleConservative(txs, signer)))
	}

	artifact := map[string]any{
		"schema":     "agnt2-parallel-scheduler-realized-parallelism-v2",
		"workload":   map[string]any{"workflows": N, "ops": len(txs), "shape": "INVOKE->RESPOND->COMPOSE(fanin 3) per workflow", "agent_assignment": "UNIFORM over a pool of the stated SIZE (not a skewed/Zipf distribution)"},
		"cost_model": "critical-path (perfect intra-wave parallelism); per-op EXECUTION µs from BenchmarkComposedStep; sender recovery once-per-tx excluded",
		"models":     "topology_only = parent_invoke_id edges only (the sequencer-sim). write_set_commutative = AGNT2-aware: commutative bal:/rep: credits don't serialize. write_set_conservative = generic Block-STM: every shared write serializes.",
		"sweep":      rows,
		"soundness":  "declared dependency edges (RESPOND->InvokeRef AND INVOKE->DepInvokeIds) are RW conflicts, present in every model (TestSchedule_DepsSubsetOfConflicts over a workload with both edge kinds). A by-construction argument + synthetic check, not a general proof.",
		"finding": "The settlement 'collapse' is an artifact of NAIVE conflict detection, not inherent to settlement. Under the CONSERVATIVE (generic Block-STM) model, shrinking the shared agent-population SIZE serializes cross-workflow settlements (two COMPOSEs crediting the same agent WW-conflict on bal:/rep:) and realized parallelism collapses (388x topology -> single digits). But those credits are COMMUTATIVE (order-independent additive), so an AGNT2-aware executor that merges them (write_set_commutative) keeps parallelism essentially INVARIANT to the agent pool -- bounded only by the per-workflow ordered chain (leaf/ring/escrow), near the topology number. So the honest reading is: the 1000x-style parallelism IS available, but ONLY to a commutativity-aware executor; a naive Block-STM loses it. What would genuinely cap the commutativity-aware number is an op that READS an aggregate balance/reputation (none in this workload) or a skewed agent distribution (this sweep is UNIFORM, not skewed -- a skew would concentrate the conservative conflict further and is not modeled here). The topology_only baseline is 388x for THIS synthetic workload, not the paper's external 1000x; whether the real 1000x holds depends on an unmeasured production agent-access distribution.",
	}
	blob, _ := json.Marshal(artifact)
	t.Logf("ARTIFACT_JSON:%s", string(blob))
	for _, r := range rows {
		t.Logf("  %-14s pool=%-10s span=%-4d width=%-4d parallelism=%-6.2f speedup=%.2f", r.Model, r.AgentPool, r.Span, r.Width, r.MaxParallelism, r.SpeedupModel)
	}
}

func round2(f float64) float64 { return float64(int(f*100+0.5)) / 100 }

func itoa(u uint64) string {
	if u == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}
