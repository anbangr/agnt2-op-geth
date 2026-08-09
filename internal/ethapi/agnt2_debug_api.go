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
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/internal/agnt2debug"
)

// Agnt2DebugAPI exposes debug methods for the E4.6 local follower harness.
// All methods are guarded by an allowlist of development chain ids (see
// agnt2DebugChainIDs) to prevent accidental use on a chain that carries value.
type Agnt2DebugAPI struct {
	b Backend
}

// agnt2DebugChainIDs is the set of chain ids on which the AGNT2 Byzantine-injection
// debug API may be used. Both are local development/test chains that never carry
// value:
//
//	9001 - the AGNT2 devnet (chain-config/devnet-agnt2), used by the e4 correctness scripts
//	 901 - the standard OP-Stack devnet L2, used by op-e2e's in-process clusters
//
// This is defense in depth, not the only gate: these methods live in the "debug" RPC
// namespace, which an operator must explicitly expose.
var agnt2DebugChainIDs = map[uint64]struct{}{
	9001: {},
	901:  {},
}

// requireAgnt2DebugChain reports an error unless chainID is an allowlisted AGNT2
// development chain.
func requireAgnt2DebugChain(chainID uint64, method string) error {
	if _, ok := agnt2DebugChainIDs[chainID]; !ok {
		return fmt.Errorf("%s is only available on AGNT2 development chains (chain_id 9001 or 901), got %d", method, chainID)
	}
	return nil
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
// Only works on an allowlisted AGNT2 development chain (see agnt2DebugChainIDs).
func (api *Agnt2DebugAPI) SetBadRoot(ctx context.Context, blockNumber uint64, badRoot common.Hash) error {
	chainID, err := api.chainID(ctx)
	if err != nil {
		return err
	}
	if err := requireAgnt2DebugChain(chainID, "debug_setBadRoot"); err != nil {
		return err
	}
	agnt2debug.SetBadRoot(blockNumber, badRoot)
	return nil
}

// SetBadOrder injects a dep-ordering violation at blockNumber by specifying
// swap indices into the typed-tx slice. The sequencer will swap those two typed
// transactions before computing the typedOpRoot, causing a topo-order mismatch
// that the follower's block validator rejects.
// Only works on an allowlisted AGNT2 development chain (see agnt2DebugChainIDs).
func (api *Agnt2DebugAPI) SetBadOrder(ctx context.Context, blockNumber uint64, swapIndices []int) error {
	chainID, err := api.chainID(ctx)
	if err != nil {
		return err
	}
	if err := requireAgnt2DebugChain(chainID, "debug_setBadOrder"); err != nil {
		return err
	}
	if len(swapIndices) != 2 {
		return errors.New("swapIndices must have exactly 2 elements")
	}
	agnt2debug.SetBadOrder(blockNumber, swapIndices)
	return nil
}
