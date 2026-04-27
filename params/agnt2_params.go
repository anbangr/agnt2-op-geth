package params

import "github.com/ethereum/go-ethereum/common"

// AGNT2InteractionPrecompileAddress is the precompile that settles COMPOSE steps on-chain.
var AGNT2InteractionPrecompileAddress = common.HexToAddress("0x0BC2")

const (
	AGNT2BaseGas uint64 = 21000
	// AGNT2PerStepGas covers (a) the per-leaf keccak + binding + chain check
	// performed inside agnt2Interaction.Run() and (b) the post-success LOG
	// cost emitted by evmAGNT2PostHook (the per-call-mode dispatcher in
	// core/vm/evm.go) when the call is a successful, non-readonly invocation.
	//
	// Breakdown (Week 11 Phase 6, locked by TestRequiredGas_Phase6_LogCost):
	//   - 2_000 — Run() per-leaf cost (keccak + binding + chain validation,
	//             sized by F5 microbench under Apple M1 Max)
	//   - 2_405 — LOG cost: 375 base + 2 × 375 (topics) + 160 × 8 (data bytes)
	//             = 375 + 750 + 1280
	//
	// Total: 4_405. Charged inside RequiredGas() so the EVM bills the LOG
	// cost up-front; the dispatcher does NOT need to charge again at log-emit
	// time. STATICCALL rejection (revertStaticCall = 0x09) returns the same
	// charged gas as a regular revert because the EVM treats
	// ErrExecutionReverted as gas-refund-on-revert.
	AGNT2PerStepGas uint64 = 4405
	// AGNT2MaxStepsPerCall is the operational cap derived from block gas limit.
	// Interim hardcoded value for Week 11 — final value derives from chain config later
	// (deferred until upstream PrecompiledContract.RequiredGas gains a chain-config
	// or timestamp parameter; no such hook exists today).
	//
	// Ordering invariant (pinned by TestStepCountCaps_Bounds):
	//
	//   AGNT2MaxStepsPerCall = 4_500     (operational cap — fires first)
	//   maxSafeLeafCount     = 26_843_545  (uint32-overflow wrap protector — defense-in-depth)
	//
	// Derivation (Week 11 Phase 6):
	//   Block gas limit:        30_000_000  (Base / Optimism testnets)
	//   Required headroom:       ≥30% (i.e. precompile call ≤ 70% of block = 21_000_000)
	//   AGNT2BaseGas:                 21_000
	//   AGNT2PerStepGas:               4_405 (Run + LOG)
	//
	//   max_steps = (21_000_000 - 21_000) / 4_405 ≈ 4_762
	//
	// Rounded down to 4_500 for clean number with extra cushion:
	//   total = 21_000 + 4_500 × 4_405 = 19_843_500 ≈ 66% of block (34% headroom).
	//
	// The wrap protector in core/vm/agnt2_interaction.go sits ABOVE this operational
	// cap; AGNT2MaxStepsPerCall is the tighter (smaller) cap that always fires first
	// in both RequiredGas and Run. The wrap protector is logically unreachable under
	// the current ordering, kept as defense-in-depth in case a future bump to this
	// constant lifts it past the wrap protector — at which point the test invariant
	// fires before the silent disable.
	AGNT2MaxStepsPerCall uint64 = 4500
)
