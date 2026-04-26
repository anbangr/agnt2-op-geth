package params

import "github.com/ethereum/go-ethereum/common"

// AGNT2InteractionPrecompileAddress is the precompile that settles COMPOSE steps on-chain.
var AGNT2InteractionPrecompileAddress = common.HexToAddress("0x0BC2")

const (
	AGNT2BaseGas    uint64 = 21000
	AGNT2PerStepGas uint64 = 2000
	// AGNT2MaxStepsPerCall is the operational cap derived from block gas limit.
	// Interim hardcoded value for Week 11 — final value derives from chain config later
	// (deferred until upstream PrecompiledContract.RequiredGas gains a chain-config
	// or timestamp parameter; no such hook exists today).
	//
	// Ordering invariant (pinned by TestStepCountCaps_Bounds):
	//
	//   AGNT2MaxStepsPerCall = 10_000   (operational cap — fires first)
	//   maxSafeLeafCount     = 26_843_545  (uint32-overflow wrap protector — defense-in-depth)
	//
	// The wrap protector in core/vm/agnt2_interaction.go sits ABOVE this operational
	// cap; AGNT2MaxStepsPerCall is the tighter (smaller) cap that always fires first
	// in both RequiredGas and Run. The wrap protector is logically unreachable under
	// the current ordering, kept as defense-in-depth in case a future bump to this
	// constant lifts it past the wrap protector — at which point the test invariant
	// fires before the silent disable.
	AGNT2MaxStepsPerCall uint64 = 10_000
)
