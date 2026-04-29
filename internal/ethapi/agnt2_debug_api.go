package ethapi

import (
	"context"
	"errors"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

// agnt2DebugState holds injected bad-root / bad-order overrides for testing.
// Only active when chain_id == 9001 (E4.6 local follower harness).
var agnt2DebugState struct {
	mu         sync.Mutex
	badRoots   map[uint64]common.Hash // blockNumber → injected bad typedOpRoot
	badOrders  map[uint64][]int       // blockNumber → swap indices for dep reorder
}

func init() {
	agnt2DebugState.badRoots = make(map[uint64]common.Hash)
	agnt2DebugState.badOrders = make(map[uint64][]int)
}

// Agnt2DebugAPI exposes debug methods for the E4.6 local follower harness.
// All methods are guarded by chain_id == 9001 to prevent accidental use on mainnet.
type Agnt2DebugAPI struct {
	b Backend
}

// NewAgnt2DebugAPI creates an Agnt2DebugAPI instance.
func NewAgnt2DebugAPI(b Backend) *Agnt2DebugAPI {
	return &Agnt2DebugAPI{b: b}
}

func (api *Agnt2DebugAPI) chainID(ctx context.Context) (uint64, error) {
	chainConfig := api.b.ChainConfig()
	if chainConfig == nil || chainConfig.ChainID == nil {
		return 0, errors.New("chain config unavailable")
	}
	return chainConfig.ChainID.Uint64(), nil
}

// SetBadRoot injects a bad typedOpRoot for blockNumber. On the next block at that
// number the sequencer will emit a block whose TypedOpRoot mismatches the real root,
// causing the follower's block validator to increment engine_invalid_block_count.
// Only works when chain_id == 9001.
func (api *Agnt2DebugAPI) SetBadRoot(ctx context.Context, blockNumber uint64, badRoot common.Hash) error {
	chainID, err := api.chainID(ctx)
	if err != nil {
		return err
	}
	if chainID != 9001 {
		return errors.New("debug_setBadRoot is only available on chain_id 9001")
	}
	agnt2DebugState.mu.Lock()
	defer agnt2DebugState.mu.Unlock()
	agnt2DebugState.badRoots[blockNumber] = badRoot
	return nil
}

// SetBadOrder injects a dep-ordering violation at blockNumber by specifying
// swap indices into the typed-tx slice. The sequencer will swap those two typed
// transactions before computing the typedOpRoot, causing a topo-order mismatch
// that the follower's block validator rejects.
// Only works when chain_id == 9001.
func (api *Agnt2DebugAPI) SetBadOrder(ctx context.Context, blockNumber uint64, swapIndices []int) error {
	chainID, err := api.chainID(ctx)
	if err != nil {
		return err
	}
	if chainID != 9001 {
		return errors.New("debug_setBadOrder is only available on chain_id 9001")
	}
	if len(swapIndices) != 2 {
		return errors.New("swapIndices must have exactly 2 elements")
	}
	agnt2DebugState.mu.Lock()
	defer agnt2DebugState.mu.Unlock()
	agnt2DebugState.badOrders[blockNumber] = swapIndices
	return nil
}

// GetBadRoot returns the injected bad root for blockNumber (zero hash = none).
// Used internally by the block-building pipeline.
func GetAgnt2BadRoot(blockNumber uint64) (common.Hash, bool) {
	agnt2DebugState.mu.Lock()
	defer agnt2DebugState.mu.Unlock()
	h, ok := agnt2DebugState.badRoots[blockNumber]
	if ok {
		delete(agnt2DebugState.badRoots, blockNumber)
	}
	return h, ok
}

// GetBadOrder returns the injected swap indices for blockNumber (nil = none).
func GetAgnt2BadOrder(blockNumber uint64) ([]int, bool) {
	agnt2DebugState.mu.Lock()
	defer agnt2DebugState.mu.Unlock()
	s, ok := agnt2DebugState.badOrders[blockNumber]
	if ok {
		delete(agnt2DebugState.badOrders, blockNumber)
	}
	return s, ok
}
