// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package ethapi

import (
	"context"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/internal/agnt2debug"
)

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
	agnt2debug.SetBadRoot(blockNumber, badRoot)
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
	agnt2debug.SetBadOrder(blockNumber, swapIndices)
	return nil
}
