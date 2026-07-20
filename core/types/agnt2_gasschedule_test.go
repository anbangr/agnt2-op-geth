package types

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
)

// The capability-weighted gas schedule (agnt2_gasschedule.go) is the uncalibrated
// per-op generalization of the flat model. These tests lock its mechanics: each op
// prices identically to the flat model under default coefficients, each of the four
// dimensions is charged deterministically, the honest sub-linear-COMPOSE result is
// base-amortization (NOT a manufactured crossover), a cross-language golden vector
// holds, and — driven as FoldTypedGasSchedule — it folds EXACTLY the ops the re-exec
// fraud fold folds across every skip class.

// TestGasSchedule_DefaultMatchesFlatModel: under DefaultGasScheduleParams each op is
// priced exactly as the flat per-call formula (core/vm RequiredGas) prices it — a
// single INVOKE/RESPOND is AGNT2BaseGas+AGNT2PerStepGas, β=0 makes payload size
// irrelevant, and a COMPOSE over K children is Base+K*PerStep (GammaFanIn=PerStep).
func TestGasSchedule_DefaultMatchesFlatModel(t *testing.T) {
	p := DefaultGasScheduleParams()
	flat := params.AGNT2BaseGas + params.AGNT2PerStepGas // 25405

	if g := p.Cost(GasOp{OpType: agnt2StepTypeInvoke}); g != flat {
		t.Fatalf("INVOKE default cost=%d want flat %d", g, flat)
	}
	if g := p.Cost(GasOp{OpType: agnt2StepTypeRespond}); g != flat {
		t.Fatalf("RESPOND default cost=%d want flat %d", g, flat)
	}
	// β=0 ⇒ DA payload size cannot change the price.
	small := p.Cost(GasOp{OpType: agnt2StepTypeInvoke, DABytes: 0})
	huge := p.Cost(GasOp{OpType: agnt2StepTypeInvoke, DABytes: 1 << 20})
	if small != huge {
		t.Fatalf("β=0 but payload changed price: %d vs %d", small, huge)
	}
	// COMPOSE over 3 children == flat 3-step price (base amortized once); GammaDepth=0.
	wantCompose := params.AGNT2BaseGas + 3*params.AGNT2PerStepGas // 34215
	if g := p.Cost(GasOp{OpType: agnt2StepTypeCompose, FanIn: 3, Depth: 1}); g != wantCompose {
		t.Fatalf("COMPOSE(3) default cost=%d want %d", g, wantCompose)
	}
}

// TestGasSchedule_PerCapabilityBaseCost: RoleWeight adds a per-capability base
// surcharge; an unknown role (incl. RESPOND/COMPOSE which carry no role) adds 0.
func TestGasSchedule_PerCapabilityBaseCost(t *testing.T) {
	p := DefaultGasScheduleParams()
	p.RoleWeight = map[string]uint64{"planner": 5000, "solver": 2000}
	base := params.AGNT2BaseGas + params.AGNT2PerStepGas // 25405

	planner := p.Cost(GasOp{OpType: agnt2StepTypeInvoke, Role: "planner"})
	solver := p.Cost(GasOp{OpType: agnt2StepTypeInvoke, Role: "solver"})
	ghost := p.Cost(GasOp{OpType: agnt2StepTypeInvoke, Role: "ghost"})

	if planner != base+5000 {
		t.Fatalf("planner=%d want %d", planner, base+5000)
	}
	if solver != base+2000 {
		t.Fatalf("solver=%d want %d", solver, base+2000)
	}
	if ghost != base {
		t.Fatalf("unknown role should add 0: got %d want %d", ghost, base)
	}
	// A role name equal to a Go builtin-ish string (or any absent key) adds 0 — Go
	// maps have no prototype chain. This pins the invariant the TS twin must match
	// (its plain-object lookup must NOT read Object.prototype members).
	for _, r := range []string{"toString", "constructor", "__proto__", "valueOf", "hasOwnProperty"} {
		if g := p.Cost(GasOp{OpType: agnt2StepTypeInvoke, Role: r}); g != base {
			t.Fatalf("role %q should add 0 (absent key): got %d want %d", r, g, base)
		}
	}
	if planner == solver || solver == ghost {
		t.Fatal("capability classes must be distinguishable")
	}
}

// TestGasSchedule_PayloadSurchargeLinearInBytes: with β>0, cost rises by exactly β
// per DA byte committed, regardless of op type.
func TestGasSchedule_PayloadSurchargeLinearInBytes(t *testing.T) {
	p := DefaultGasScheduleParams()
	p.BetaDAGasPerByte = 16

	for _, n := range []uint64{1, 2, 7, 64, 1000} {
		a := p.Cost(GasOp{OpType: agnt2StepTypeInvoke, DABytes: n - 1})
		b := p.Cost(GasOp{OpType: agnt2StepTypeInvoke, DABytes: n})
		if b-a != 16 {
			t.Fatalf("marginal DA gas at n=%d: %d want 16", n, b-a)
		}
	}
	base := params.AGNT2BaseGas + params.AGNT2PerStepGas
	if g := p.Cost(GasOp{OpType: agnt2StepTypeInvoke, DABytes: 100}); g != base+1600 {
		t.Fatalf("cost with 100 DA bytes=%d want %d", g, base+1600)
	}
}

// TestGasSchedule_FanInAndDepthSurcharge: a COMPOSE's compute rises by GammaFanIn
// per aggregated child and GammaDepth per aggregation level.
func TestGasSchedule_FanInAndDepthSurcharge(t *testing.T) {
	p := DefaultGasScheduleParams()
	p.GammaDepth = 1000 // exercise depth (default 0 makes it inert in the fold)

	if g := p.Cost(GasOp{OpType: agnt2StepTypeCompose, FanIn: 0, Depth: 0}); g != params.AGNT2BaseGas {
		t.Fatalf("empty COMPOSE=%d want Base %d", g, params.AGNT2BaseGas)
	}
	c2 := p.Cost(GasOp{OpType: agnt2StepTypeCompose, FanIn: 2, Depth: 1})
	c3 := p.Cost(GasOp{OpType: agnt2StepTypeCompose, FanIn: 3, Depth: 1})
	if c3-c2 != params.AGNT2PerStepGas {
		t.Fatalf("marginal fan-in gas=%d want %d", c3-c2, params.AGNT2PerStepGas)
	}
	d1 := p.Cost(GasOp{OpType: agnt2StepTypeCompose, FanIn: 3, Depth: 1})
	d2 := p.Cost(GasOp{OpType: agnt2StepTypeCompose, FanIn: 3, Depth: 2})
	if d2-d1 != 1000 {
		t.Fatalf("marginal depth gas=%d want 1000", d2-d1)
	}
}

// TestGasSchedule_ReputationDiscountsComputeNotDA: reputation discounts the compute
// component only; the DA externality (β·bytes) is charged in full and is invariant
// to reputation. Out-of-range / unset bps ⇒ full price (never a surcharge).
func TestGasSchedule_ReputationDiscountsComputeNotDA(t *testing.T) {
	p := DefaultGasScheduleParams()
	p.BetaDAGasPerByte = 16
	const daBytes = 100
	daTerm := uint64(16 * daBytes) // 1600, must be reputation-invariant
	compute := params.AGNT2BaseGas + params.AGNT2PerStepGas

	full := p.Cost(GasOp{OpType: agnt2StepTypeInvoke, DABytes: daBytes, RepBps: ReputationFullBps})
	if full != compute+daTerm {
		t.Fatalf("full price=%d want %d", full, compute+daTerm)
	}
	half := p.Cost(GasOp{OpType: agnt2StepTypeInvoke, DABytes: daBytes, RepBps: 5000})
	wantHalf := compute*5000/10000 + daTerm // 12702 + 1600
	if half != wantHalf {
		t.Fatalf("half-rep price=%d want %d", half, wantHalf)
	}
	if (full - compute) != (half - compute*5000/10000) {
		t.Fatal("DA surcharge must be invariant to reputation")
	}
	if p.Cost(GasOp{OpType: agnt2StepTypeInvoke, DABytes: daBytes, RepBps: 0}) != full {
		t.Fatal("RepBps=0 must mean full price")
	}
	if p.Cost(GasOp{OpType: agnt2StepTypeInvoke, DABytes: daBytes, RepBps: 20000}) != full {
		t.Fatal("RepBps>10000 must clamp to full price (reputation cannot surcharge)")
	}
}

// TestGasSchedule_ReputationFloor: MinRepBps floors the discount. It documents the
// spam surface Layer A ships with — floorless (default MinRepBps=0), a maximally-
// trusted agent's compute charge approaches zero — and that a non-zero floor caps it.
func TestGasSchedule_ReputationFloor(t *testing.T) {
	compute := params.AGNT2BaseGas + params.AGNT2PerStepGas // 25405

	// Floorless default: RepBps=1 drives compute to floor(25405/10000)=2. This is the
	// unacknowledged-no-longer spam surface; Layer A makes NO spam-resistance claim.
	noFloor := DefaultGasScheduleParams()
	if g := noFloor.Cost(GasOp{OpType: agnt2StepTypeInvoke, RepBps: 1}); g != compute*1/10000 {
		t.Fatalf("floorless RepBps=1 cost=%d want %d (documents the spam surface)", g, compute*1/10000)
	}

	// With a floor, the discount cannot go below it.
	p := DefaultGasScheduleParams()
	p.MinRepBps = 3000
	if g := p.Cost(GasOp{OpType: agnt2StepTypeInvoke, RepBps: 1}); g != compute*3000/10000 {
		t.Fatalf("floored RepBps=1 cost=%d want %d", g, compute*3000/10000)
	}
	// The floor never raises a good-reputation op above full price.
	if g := p.Cost(GasOp{OpType: agnt2StepTypeInvoke, RepBps: ReputationFullBps}); g != compute {
		t.Fatalf("floor raised full-price op: got %d want %d", g, compute)
	}
}

// TestGasSchedule_ComposeSettlementAmortization is the HONEST sub-linear-COMPOSE
// result — base amortization, with REAL measured DA envelope byte counts and no
// side's DA zeroed. Earlier drafts manufactured a β-crossover by pricing the
// unbundled INVOKEs at DABytes=0 (impossible in the fold); this test replaces that.
func TestGasSchedule_ComposeSettlementAmortization(t *testing.T) {
	// Settle K=3 independent results two ways. Measured envelope lengths:
	//   an INVOKE envelope (empty callData)      = 128 bytes
	//   a COMPOSE envelope over K children       = 192 + 32*K bytes (=288 at K=3)
	const K = 3
	base := params.AGNT2BaseGas
	const invokeEnv = 128
	const composeEnv = 192 + 32*K // 288

	unbundled := func(beta uint64) uint64 { // K separate settlement ops
		p := DefaultGasScheduleParams()
		p.BetaDAGasPerByte = beta
		return K * p.Cost(GasOp{OpType: agnt2StepTypeInvoke, DABytes: invokeEnv})
	}
	bundled := func(beta uint64) uint64 { // one COMPOSE aggregating the K results
		p := DefaultGasScheduleParams()
		p.BetaDAGasPerByte = beta
		return p.Cost(GasOp{OpType: agnt2StepTypeCompose, FanIn: K, Depth: 1, DABytes: composeEnv})
	}

	// (1) The only honest sub-linearity claim: at β=0 bundling saves EXACTLY
	// (K-1)*Base, because a COMPOSE pays ONE base instead of K. This is the SAME
	// sign the flat model already exhibits (GammaFanIn=PerStep) — by construction,
	// not an emergent property of capability-weighting.
	if got := unbundled(0) - bundled(0); got != (K-1)*base {
		t.Fatalf("β=0 base amortization=%d want (K-1)*Base=%d", got, (K-1)*base)
	}

	// (2) With REAL per-op envelopes the advantage is ROBUST: the COMPOSE commits
	// FEWER DA bytes (288) than K separate op envelopes (3*128=384), so bundling
	// wins for ALL β and the advantage GROWS with β. There is NO realistic crossover.
	prevAdv := unbundled(0) - bundled(0)
	for _, beta := range []uint64{1, 100, 1000, 1_000_000} {
		if bundled(beta) >= unbundled(beta) {
			t.Fatalf("β=%d: bundled %d must stay below unbundled %d (COMPOSE commits fewer bytes)", beta, bundled(beta), unbundled(beta))
		}
		if adv := unbundled(beta) - bundled(beta); adv < prevAdv {
			t.Fatalf("β=%d: advantage %d shrank (was %d)", beta, adv, prevAdv)
		} else {
			prevAdv = adv
		}
	}

	// (3) HONEST caveat: a sign-flip appears ONLY under a DIFFERENT accounting where
	// the unbundled ops commit their BARE 32-byte result while the COMPOSE still pays
	// its bytes32[] framing — an accounting choice, not a neutral break-even. Whether
	// that regime is realistic is a Phase-2 calibration question; Layer A asserts NO
	// economic crossover, only that the sign is accounting-dependent.
	bareUnbundled := func(beta uint64) uint64 {
		p := DefaultGasScheduleParams()
		p.BetaDAGasPerByte = beta
		return K * p.Cost(GasOp{OpType: agnt2StepTypeInvoke, DABytes: 32})
	}
	if bundled(100_000) <= bareUnbundled(100_000) {
		t.Fatal("under bare-hash accounting the sign should flip at large β (demonstrates accounting-dependence)")
	}
}

// TestGasSchedule_GoldenCrossLang locks GasScheduleParams.Cost byte-identical to the
// TS twin (benchmarks/src/gas-schedule.ts) via golden/typed-gas-schedule/
// gas-schedule-vectors.json. Values embedded as constants (same discipline as
// TestReexecLeaf_GoldenCrossLang); the JSON is the shared oracle both sides assert.
func TestGasSchedule_GoldenCrossLang(t *testing.T) {
	golden := GasScheduleParams{
		Base: 21000, PerStep: 4405, GammaFanIn: 4405, GammaDepth: 1000, BetaDAGasPerByte: 16,
		RoleWeight: map[string]uint64{"planner": 5000, "solver": 2000},
	}
	cases := []struct {
		op   GasOp
		want uint64
	}{
		{GasOp{OpType: agnt2StepTypeInvoke, Role: "planner", DABytes: 100, RepBps: 10000}, 32005},
		{GasOp{OpType: agnt2StepTypeInvoke, Role: "solver", DABytes: 64, RepBps: 8000}, 22948},
		{GasOp{OpType: agnt2StepTypeInvoke, Role: "unknown-role", DABytes: 0, RepBps: 0}, 25405},
		{GasOp{OpType: agnt2StepTypeInvoke, Role: "__proto__", DABytes: 0, RepBps: 10000}, 25405}, // prototype-key role => absent => 0 surcharge (Go/TS parity)
		{GasOp{OpType: agnt2StepTypeRespond, Role: "", DABytes: 200, RepBps: 10000}, 28605},
		{GasOp{OpType: agnt2StepTypeCompose, FanIn: 3, Depth: 1, DABytes: 288, RepBps: 10000}, 39823},
		{GasOp{OpType: agnt2StepTypeCompose, FanIn: 3, Depth: 1, DABytes: 288, RepBps: 6000}, 25737},
	}
	for i, c := range cases {
		if g := golden.Cost(c.op); g != c.want {
			t.Fatalf("golden op[%d] cost=%d want %d", i, g, c.want)
		}
	}
	// DA surcharge invariance across the two COMPOSE ops (both 16*288=4608).
	if (golden.Cost(cases[5].op) - 35215) != (golden.Cost(cases[6].op) - 21129) {
		t.Fatal("golden COMPOSE DA surcharge must be reputation-invariant")
	}
}

// TestFoldTypedGasSchedule_MatchesReexecFold drives BOTH folds over a fixture per
// skip class and asserts, for each: (a) the gas fold charges the EXACT expected
// op-set (charges[].TxHash == the hand-specified set that should fold — an identity
// check, not just a count), (b) the gas fold's op count equals the reexec fraud
// fold's opCount (cross-fold count parity), and (c) total == sum(charges). (a)+(b)
// together keep the charged op-set equal to the fraud-covered op-set even though the
// two folds are hand-maintained parallels: (a) pins the gas fold to a known-correct
// set, (b) cross-checks it against the independent reexec fold, so a drift that folds
// op X in place of op Y (counts equal, sets differ) is caught by (a).
func TestFoldTypedGasSchedule_MatchesReexecFold(t *testing.T) {
	key := composeFoldTestKey(t)
	signer := LatestSignerForChainID(big.NewInt(9001))
	wf := common.HexToHash("0xC0")

	// Happy path — all three fold.
	invoke := mkFoldInvoke(t, signer, key, 0, wf, []byte("call"))
	respond := mkFoldRespond(t, signer, key, 1, wf, invoke.Hash())
	compose := mkFoldCompose(t, signer, key, 2, wf)

	// M6: a RESPOND whose parent is not in-block and no resolver => skipped by both.
	orphan := mkFoldRespond(t, signer, key, 3, common.HexToHash("0xBEEF"), common.HexToHash("0xDEAD"))

	// Unknown tx type (legacy) => skipped by both, before any signer check.
	to := common.HexToAddress("0x00000000000000000000000000000000DeaDBeef")
	legacy := NewTx(&LegacyTx{Nonce: 9, To: &to, Gas: 21000, GasPrice: big.NewInt(1)})

	// Cross-block RESPOND resolved via a non-nil resolver => folded by both.
	xbWf := common.HexToHash("0xCB")
	xbRef := common.HexToHash("0x1234")
	xbRespond := mkFoldRespond(t, signer, key, 4, xbWf, xbRef)
	resolver := func(ref common.Hash) (common.Hash, bool) {
		if ref == xbRef {
			return common.HexToHash("0xabc123"), true
		}
		return common.Hash{}, false
	}

	cases := []struct {
		name     string
		txs      []*Transaction
		resolver ReexecParentResolver
		expect   []*Transaction // the EXACT ops that should fold (identity, not just count)
	}{
		{"happy-all-fold", []*Transaction{invoke, respond, compose}, nil, []*Transaction{invoke, respond, compose}},
		{"lone-empty-compose-skip", []*Transaction{compose}, nil, nil},
		{"m6-orphan-respond-skip", []*Transaction{orphan}, nil, nil},
		{"unknown-type-interleaved", []*Transaction{invoke, legacy, respond, compose}, nil, []*Transaction{invoke, respond, compose}},
		{"nil-tx-interleaved", []*Transaction{nil, invoke, nil, respond}, nil, []*Transaction{invoke, respond}},
		{"cross-block-respond-via-resolver", []*Transaction{xbRespond}, resolver, []*Transaction{xbRespond}},
	}
	for _, c := range cases {
		_, count := FoldTypedReexecRoot(c.txs, signer, c.resolver)
		total, charges := FoldTypedGasSchedule(c.txs, signer, c.resolver, DefaultGasScheduleParams(), nil)

		// (b) cross-fold count parity.
		if uint64(len(charges)) != count {
			t.Fatalf("%s: gas fold charged %d ops but reexec fold folded %d", c.name, len(charges), count)
		}
		// (a) exact op-set identity: the charged tx-hashes are precisely the expected set.
		want := make(map[common.Hash]bool, len(c.expect))
		for _, tx := range c.expect {
			want[tx.Hash()] = true
		}
		got := make(map[common.Hash]bool, len(charges))
		for _, ch := range charges {
			got[ch.TxHash] = true
		}
		if len(got) != len(want) {
			t.Fatalf("%s: charged %d distinct ops, expected %d", c.name, len(got), len(want))
		}
		for h := range want {
			if !got[h] {
				t.Fatalf("%s: expected op %x not charged (gas fold folded a different op-set)", c.name, h)
			}
		}
		// (c) total is the sum of per-op charges.
		var sum uint64
		for _, ch := range charges {
			sum += ch.Gas
		}
		if sum != total {
			t.Fatalf("%s: charge sum %d != total %d", c.name, sum, total)
		}
	}
}

// TestFoldTypedGasSchedule_DefaultPricingAndReputation: per-op default gas matches
// the flat/amortized model, and a reputation oracle discounts every op's compute
// (β=0 ⇒ no DA term). Separated from the parity test so each locks one property.
func TestFoldTypedGasSchedule_DefaultPricingAndReputation(t *testing.T) {
	key := composeFoldTestKey(t)
	signer := LatestSignerForChainID(big.NewInt(9001))
	wf := common.HexToHash("0xC0")
	invoke := mkFoldInvoke(t, signer, key, 0, wf, []byte("call"))
	respond := mkFoldRespond(t, signer, key, 1, wf, invoke.Hash())
	compose := mkFoldCompose(t, signer, key, 2, wf)
	txs := []*Transaction{invoke, respond, compose}

	total, charges := FoldTypedGasSchedule(txs, signer, nil, DefaultGasScheduleParams(), nil)

	flat := params.AGNT2BaseGas + params.AGNT2PerStepGas          // 25405
	wantCompose := params.AGNT2BaseGas + 2*params.AGNT2PerStepGas // fanIn=2 (invoke+respond), 29810
	wantTotal := flat + flat + wantCompose                        // 80620
	if total != wantTotal {
		t.Fatalf("default fold total=%d want %d", total, wantTotal)
	}
	if charges[2].OpType != agnt2StepTypeCompose || charges[2].FanIn != 2 || charges[2].Gas != wantCompose {
		t.Fatalf("COMPOSE charge=%+v want opType=3 fanIn=2 gas=%d", charges[2], wantCompose)
	}

	// Reputation oracle halves compute for every op; β=0 so no DA term survives.
	rep := func(common.Address) uint64 { return 5000 }
	dTotal, _ := FoldTypedGasSchedule(txs, signer, nil, DefaultGasScheduleParams(), rep)
	wantDiscounted := flat*5000/10000*2 + wantCompose*5000/10000 // 12702*2 + 14905 = 40309
	if dTotal != wantDiscounted {
		t.Fatalf("discounted fold total=%d want %d", dTotal, wantDiscounted)
	}
	if !(dTotal < total) {
		t.Fatalf("reputation discount did not reduce total: %d !< %d", dTotal, total)
	}
}
