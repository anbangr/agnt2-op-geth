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

package eth

import (
	"testing"

	"github.com/ethereum/go-ethereum/core"
)

// TestAdminAPI_Metrics verifies that AdminAPI.Metrics returns the current
// engine_invalid_block_count from core.Agnt2InvalidSignatureCount.
// Metrics() does not use the eth.Ethereum backend — a nil receiver is safe.
func TestAdminAPI_Metrics(t *testing.T) {
	api := &AdminAPI{eth: nil}

	core.Agnt2InvalidSignatureCount.Store(0)
	m := api.Metrics()
	if v, ok := m["engine_invalid_block_count"]; !ok {
		t.Fatal("Metrics() missing engine_invalid_block_count key")
	} else if v.(uint64) != 0 {
		t.Fatalf("expected 0, got %v", v)
	}

	core.Agnt2InvalidSignatureCount.Store(7)
	m = api.Metrics()
	if v := m["engine_invalid_block_count"].(uint64); v != 7 {
		t.Fatalf("expected 7, got %v", v)
	}

	// Reset to avoid affecting other tests that read the counter.
	core.Agnt2InvalidSignatureCount.Store(0)
}
