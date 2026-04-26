package params

import "github.com/ethereum/go-ethereum/common"

// AGNT2InteractionPrecompileAddress is the precompile that settles COMPOSE steps on-chain.
var AGNT2InteractionPrecompileAddress = common.HexToAddress("0x0BC2")

const (
	AGNT2_BASE_GAS     uint64 = 21000
	AGNT2_PER_STEP_GAS uint64 = 2000
)
