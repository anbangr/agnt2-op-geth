package types

// AGNT2 capability-weighted gas schedule (research-grade T3, Layer A).
//
// The production op-geth precompile prices a typed op with a FLAT model —
// params.AGNT2BaseGas + stepCount*params.AGNT2PerStepGas (see
// core/vm/agnt2_interaction.go RequiredGas). That is deliberately capability-
// BLIND: an INVOKE that commits 8 bytes to DA and one that commits 120 KB pay
// the same, and a COMPOSE that aggregates K steps is priced by its own stepCount
// alone. This module is the *uncalibrated* generalization: a pure, deterministic
// gas function with four pricing dimensions — a per-capability (AgentRole) base
// weight, a payload-bytes-committed-to-DA surcharge (coefficient β), a
// fan-in/depth aggregation surcharge on COMPOSE, and a reputation discount. It is
// the Go half of a Go+TS golden pair (benchmarks/src/gas-schedule.ts), mirroring
// the FoldTypedReexecRoot cross-language discipline.
//
// RELATION TO THE FLAT MODEL (precise — it is a per-op generalization, not a
// block-level repricing): under DefaultGasScheduleParams each typed op is priced
// EXACTLY as the flat per-call formula prices that op — a single INVOKE/RESPOND is
// Base+PerStep, and a COMPOSE aggregating K children is Base+K*PerStep (because
// GammaFanIn defaults to PerStep, NOT zero — it is the one non-zero default, and
// it is precisely what makes the COMPOSE collapse to the flat K-step price). The
// other three dimensions are zero/identity by default (β=0, GammaDepth=0,
// RoleWeight nil, reputation full), so they contribute nothing until calibrated.
// A block's schedule total is the SUM of these per-op flat prices; that equals the
// flat precompile total exactly when each precompile call settles one typed op
// (the typed-tx model — one op per tx), which is the case the fold walks.
//
// SCOPE (honest, do not overstate): Layer A wires a *parameterized* hook and
// proves its mechanics deterministically. It is NOT consensus-active — nothing
// here is called from RequiredGas — and it is UNCALIBRATED: β, the role weights,
// GammaDepth, and the reputation floor are levers, not fitted values. Phase 2
// fits β to a real measured Celestia fee; only then can the schedule make any
// quantitative economic claim. In particular this module makes NO spam-resistance
// claim (see the reputation note below).
//
// DA externality (Pigouvian split): the β·bytes surcharge models a real external
// cost — bytes the operator must pay Celestia to store — so it is charged in FULL
// and is NOT reputation-discountable, and being linear per-byte with no per-op
// floor it is split-proof (fragmenting a payload preserves total bytes). Only the
// compute component (Base + role + fan-in + depth) is discounted by reputation.

import (
	"github.com/ethereum/go-ethereum/common"
	gethmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/params"
)

// ReputationFullBps is the no-discount reputation multiplier (100.00%). Basis
// points (1/10000) keep the discount deterministic under integer arithmetic —
// no floats ever enter a gas computation.
const ReputationFullBps uint64 = 10000

// GasScheduleParams are the (uncalibrated) coefficients of the capability-weighted
// schedule. DefaultGasScheduleParams collapses each op to its flat-model price.
type GasScheduleParams struct {
	// Base is the fixed per-op admission/settlement cost — the amount a COMPOSE
	// amortizes when it settles K steps in one op instead of K. Default
	// params.AGNT2BaseGas.
	Base uint64
	// PerStep is the per-step compute cost charged to an INVOKE/RESPOND (one step
	// each). Default params.AGNT2PerStepGas.
	PerStep uint64
	// GammaFanIn is the compute charged per aggregated child on a COMPOSE. This is
	// the cost of BINDING a child's committed output into the atomic aggregate —
	// conceptually distinct from the child's own execution PerStep (which the child
	// op is charged separately). Its default, params.AGNT2PerStepGas, is an
	// UNCALIBRATED placeholder chosen so a COMPOSE over K children reproduces the
	// flat K-step price (Base+K*PerStep); it is not a claim that binding a 32-byte
	// hash costs as much as executing a LOG-emitting step. Calibration may lower it.
	GammaFanIn uint64
	// GammaDepth is the compute charged per aggregation LEVEL on a COMPOSE. Default
	// 0 (uncalibrated). NOTE: the in-block fold sets Depth=1 for every COMPOSE, so
	// with the default this term is inert in every folded block; multi-level depth
	// accounting is a calibration-phase extension exercised only by direct Cost()
	// calls, not by the delivered fold.
	GammaDepth uint64
	// BetaDAGasPerByte (β) is gas charged per byte the op commits to DA. Default 0 —
	// Layer A does not invent a DA price; Phase 2 fits β to a measured Celestia fee.
	// At β=0 the schedule ignores payload size (like the flat model).
	BetaDAGasPerByte uint64
	// MinRepBps is a floor on the reputation multiplier: effBps is never discounted
	// below it. Default 0 = NO floor — meaning a maximally-trusted agent's compute
	// charge can approach zero. A production deployment MUST set a non-zero floor
	// (and a non-zero β) for the schedule to resist spam; Layer A ships floorless
	// and makes no spam-resistance claim. Capped at ReputationFullBps.
	MinRepBps uint64
	// RoleWeight is an additive per-capability (AgentRole) base surcharge. A role
	// absent from the map (incl. a nil map, incl. RESPOND/COMPOSE which carry no
	// role) contributes 0. Default nil.
	RoleWeight map[string]uint64
}

// DefaultGasScheduleParams returns the coefficients under which each typed op is
// priced exactly as the flat per-call formula prices it: a single INVOKE/RESPOND
// == params.AGNT2BaseGas + params.AGNT2PerStepGas, and a COMPOSE over K children
// == Base + K*PerStep. β=0, GammaDepth=0, no floor, no role weights, no discount;
// GammaFanIn=PerStep (the single non-zero default) is what makes the COMPOSE match
// the flat K-step price. TestGasSchedule_DefaultMatchesFlatModel locks this.
func DefaultGasScheduleParams() GasScheduleParams {
	return GasScheduleParams{
		Base:             params.AGNT2BaseGas,
		PerStep:          params.AGNT2PerStepGas,
		GammaFanIn:       params.AGNT2PerStepGas, // NOT zero — see field doc
		GammaDepth:       0,
		BetaDAGasPerByte: 0,
		MinRepBps:        0,
		RoleWeight:       nil,
	}
}

// GasOp is the capability-bearing description of one typed op, sufficient to
// price it. FanIn/Depth are meaningful only for COMPOSE (0 otherwise); DABytes is
// the length of the op's DA-committed stepPayload envelope; RepBps is the agent's
// reputation multiplier in basis points (0 or >10000 is treated as no discount).
type GasOp struct {
	OpType  uint8  // agnt2StepTypeInvoke | Respond | Compose
	Role    string // AgentRole for INVOKE; "" for RESPOND/COMPOSE
	DABytes uint64 // bytes committed to DA (len of the reexec stepPayload envelope)
	FanIn   uint64 // COMPOSE: number of aggregated children; else 0
	Depth   uint64 // COMPOSE: aggregation depth (fold always sets 1); else 0
	RepBps  uint64 // reputation multiplier, basis points; 0 => ReputationFullBps
}

// Cost prices a single op. Deterministic, integer-only, overflow-saturating
// (defense-in-depth — real inputs are bounded far below saturation):
//
//	compute    = Base + RoleWeight[Role] + (INVOKE/RESPOND: PerStep)
//	                                     + (COMPOSE: GammaFanIn*FanIn + GammaDepth*Depth)
//	discounted = compute * effBps / 10000              // reputation, compute only
//	gas        = discounted + BetaDAGasPerByte * DABytes // DA externality, full price
//
// effBps = RepBps clamped to (0, ReputationFullBps] and then floored at MinRepBps;
// reputation may only discount, never surcharge, and an unset (0) RepBps means
// full price. The DA surcharge is added AFTER the discount, so it is never reduced.
func (p GasScheduleParams) Cost(op GasOp) uint64 {
	compute := satAdd(p.Base, p.RoleWeight[op.Role])
	switch op.OpType {
	case agnt2StepTypeInvoke, agnt2StepTypeRespond:
		compute = satAdd(compute, p.PerStep)
	case agnt2StepTypeCompose:
		compute = satAdd(compute, satMul(p.GammaFanIn, op.FanIn))
		compute = satAdd(compute, satMul(p.GammaDepth, op.Depth))
	default:
		// Unknown op type: base + role only. Never reached from the fold (which
		// only builds the three typed ops), kept total for the pure API.
	}

	effBps := op.RepBps
	if effBps == 0 || effBps > ReputationFullBps {
		effBps = ReputationFullBps // unset or out-of-range => no discount
	}
	if floor := p.MinRepBps; floor > 0 && floor <= ReputationFullBps && effBps < floor {
		effBps = floor // reputation floor (0 => no floor)
	}
	discounted := satMul(compute, effBps) / ReputationFullBps

	daSurcharge := satMul(p.BetaDAGasPerByte, op.DABytes)
	return satAdd(discounted, daSurcharge)
}

// GasCharge is the per-op record the fold emits. It is a LATENT record — no
// in-tree consumer reads it yet — intended for a future measurement harness that
// attributes a block's typed-op gas to individual ops and dimensions.
type GasCharge struct {
	TxHash  common.Hash
	OpType  uint8
	Role    string
	DABytes uint64
	FanIn   uint64
	Depth   uint64
	RepBps  uint64
	Gas     uint64
}

// ReputationOracle maps an agent to its reputation multiplier in basis points.
// A nil oracle (or a 0 return) means full price (no discount) for every agent.
type ReputationOracle func(agent common.Address) uint64

// FoldTypedGasSchedule is the sibling accumulator to FoldTypedReexecRoot: it walks
// the block's typed ops through a fold loop that STRUCTURALLY MIRRORS the reexec
// fold (same INVOKE/RESPOND/COMPOSE handling, same cross-block parent resolution,
// same M6 / empty-child skips), and instead of MMR-folding each surviving leaf it
// PRICES it. The two folds are hand-maintained parallels, not a shared traversal,
// so their op-set parity is a regression risk, not a structural guarantee;
// TestFoldTypedGasSchedule_MatchesReexecFold drives BOTH folds over a fixture
// covering each skip class and asserts, per fixture, both the EXACT charged op-set
// (identity — charges[].TxHash equals the hand-specified set that should fold) and
// its parity with the reexec fold's opCount, which together keep the charged op-set
// equal to the fraud-covered op-set even under hand-maintained drift.
//
// stepPayload here is the very envelope the reexec fold commits, so DABytes is the
// exact byte count bound into the per-op re-exec leaf (INVOKE callData, RESPOND
// responseBytes, COMPOSE childOutputHashes). COMPOSE Depth is 1 in this in-block
// fold (one aggregation level); with the default GammaDepth=0 that term is inert.
func FoldTypedGasSchedule(
	txs []*Transaction,
	signer Signer,
	resolveParent ReexecParentResolver,
	sched GasScheduleParams,
	rep ReputationOracle,
) (uint64, []GasCharge) {
	var total uint64
	var charges []GasCharge
	opOutput := make(map[common.Hash]common.Hash)
	wfOutputs := make(map[common.Hash][][32]byte)

	repBpsFor := func(agent common.Address) uint64 {
		if rep == nil {
			return ReputationFullBps
		}
		if b := rep(agent); b != 0 {
			return b
		}
		return ReputationFullBps
	}

	for _, tx := range txs {
		if tx == nil {
			continue
		}
		var stepType uint8
		switch tx.Type() {
		case InvokeTxType:
			stepType = agnt2StepTypeInvoke
		case RespondTxType:
			stepType = agnt2StepTypeRespond
		case ComposeTypedTxType:
			// Mirror FoldTypedReexecRoot's COMPOSE branch exactly: same-block
			// same-workflow children only; empty child set => skip (no vacuous op).
			wfId, ok := tx.Agnt2ComposeWorkflowId()
			if !ok {
				continue
			}
			children := wfOutputs[wfId]
			if len(children) == 0 {
				continue
			}
			agent, err := Sender(signer, tx)
			if err != nil {
				continue
			}
			stepPayload := agnt2ComposeEnvelope([]byte{}, []byte{}, children)
			op := GasOp{
				OpType:  agnt2StepTypeCompose,
				Role:    "", // COMPOSE carries no AgentRole
				DABytes: uint64(len(stepPayload)),
				FanIn:   uint64(len(children)),
				Depth:   1,
				RepBps:  repBpsFor(agent),
			}
			gas := sched.Cost(op)
			total = satAdd(total, gas)
			charges = append(charges, GasCharge{
				TxHash: tx.Hash(), OpType: op.OpType, Role: op.Role,
				DABytes: op.DABytes, FanIn: op.FanIn, Depth: op.Depth,
				RepBps: op.RepBps, Gas: gas,
			})
			continue
		default:
			continue
		}

		opId, ok := tx.Agnt2OperationID()
		if !ok {
			continue
		}
		agent, err := Sender(signer, tx)
		if err != nil {
			continue
		}
		taskId := opId.WorkflowId

		var stepPayload []byte
		var committed common.Hash
		if stepType == agnt2StepTypeInvoke {
			callData := tx.Data()
			responseBytes := []byte{}
			committed = agnt2DeriveInvokeOutputHash(taskId, agent, callData, responseBytes)
			stepPayload = agnt2InvokeEnvelope(callData, responseBytes)
		} else {
			deps := tx.Agnt2Dependencies()
			if len(deps) == 0 {
				continue
			}
			parentOut, present := opOutput[deps[0]]
			if !present && resolveParent != nil {
				parentOut, present = resolveParent(deps[0])
			}
			if !present {
				continue // M6 skip — identical to the reexec fold
			}
			callData := []byte{}
			responseBytes := tx.Data()
			committed = agnt2DeriveRespondOutputHash(taskId, agent, parentOut, callData, responseBytes)
			stepPayload = agnt2RespondEnvelope(callData, responseBytes, parentOut)
		}

		op := GasOp{
			OpType:  stepType,
			Role:    agnt2OpRole(tx),
			DABytes: uint64(len(stepPayload)),
			RepBps:  repBpsFor(agent),
		}
		gas := sched.Cost(op)
		total = satAdd(total, gas)
		charges = append(charges, GasCharge{
			TxHash: tx.Hash(), OpType: op.OpType, Role: op.Role,
			DABytes: op.DABytes, FanIn: op.FanIn, Depth: op.Depth,
			RepBps: op.RepBps, Gas: gas,
		})

		wfOutputs[taskId] = append(wfOutputs[taskId], [32]byte(committed))
		if stepType == agnt2StepTypeInvoke {
			opOutput[tx.Hash()] = committed
		}
	}
	return total, charges
}

// agnt2OpRole extracts the capability role of a typed op: an INVOKE's AgentRole,
// "" for anything else (RESPOND/COMPOSE carry no role in the typed-VM model).
func agnt2OpRole(tx *Transaction) string {
	if itx, ok := tx.inner.(*InvokeTx); ok {
		return itx.AgentRole
	}
	return ""
}

// satMul / satAdd are overflow-saturating uint64 helpers: on overflow they return
// ^uint64(0) rather than wrapping, keeping gas deterministic. Real gas inputs are
// bounded orders of magnitude below saturation; this is pure defense-in-depth,
// matching the wrap-protector discipline in core/vm/agnt2_interaction.go.
func satMul(a, b uint64) uint64 {
	p, over := gethmath.SafeMul(a, b)
	if over {
		return ^uint64(0)
	}
	return p
}

func satAdd(a, b uint64) uint64 {
	s, over := gethmath.SafeAdd(a, b)
	if over {
		return ^uint64(0)
	}
	return s
}
