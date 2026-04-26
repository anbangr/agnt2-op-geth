package params

import "github.com/ethereum/go-ethereum/common"

// AGNT2InteractionPrecompileAddress is the precompile that settles COMPOSE steps on-chain.
var AGNT2InteractionPrecompileAddress = common.HexToAddress("0x0BC2")

const (
	AGNT2BaseGas    uint64 = 21000
	AGNT2PerStepGas uint64 = 2000
	// AGNT2MaxStepsPerCall is the operational cap derived from block gas limit.
	// Interim hardcoded value for Week 11 — final value derives from chain config later.
	// The maxSafeLeafCount = 26_843_545 in core/vm/agnt2_interaction.go remains as a
	// uint32-overflow wrap protector below this operational cap.
	AGNT2MaxStepsPerCall uint64 = 10_000
)
