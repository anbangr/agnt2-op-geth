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

// Package agnt2debug holds the shared debug-injection state for the E4.6 / E4.7
// correctness harness. It is a leaf package (no go-ethereum imports) so that the
// miner, consensus engine, and ethapi can all import it without cycles.
package agnt2debug

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

var state struct {
	mu        sync.Mutex
	badRoots  map[uint64]common.Hash // blockNumber → injected bad typedOpRoot
	badOrders map[uint64][]int       // blockNumber → swap indices for dep reorder
}

func init() {
	state.badRoots = make(map[uint64]common.Hash)
	state.badOrders = make(map[uint64][]int)
}

// SetBadRoot stores a bad typedOpRoot override for blockNumber.
// Consumed once (deleted after first read) by GetBadRoot.
func SetBadRoot(blockNumber uint64, root common.Hash) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.badRoots[blockNumber] = root
}

// SetBadOrder stores swap indices for blockNumber.
// Consumed once (deleted after first read) by GetBadOrder.
func SetBadOrder(blockNumber uint64, swapIndices []int) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.badOrders[blockNumber] = swapIndices
}

// GetBadRoot returns and clears the injected bad root for blockNumber.
// Returns (zero hash, false) if none is set.
func GetBadRoot(blockNumber uint64) (common.Hash, bool) {
	state.mu.Lock()
	defer state.mu.Unlock()
	h, ok := state.badRoots[blockNumber]
	if ok {
		delete(state.badRoots, blockNumber)
	}
	return h, ok
}

// GetBadOrder returns and clears the injected swap indices for blockNumber.
// Returns (nil, false) if none is set.
func GetBadOrder(blockNumber uint64) ([]int, bool) {
	state.mu.Lock()
	defer state.mu.Unlock()
	s, ok := state.badOrders[blockNumber]
	if ok {
		delete(state.badOrders, blockNumber)
	}
	return s, ok
}
