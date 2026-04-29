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

package agnt2debug

import (
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestSetGetBadRoot_ConsumeOnce(t *testing.T) {
	root := common.HexToHash("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	SetBadRoot(42, root)

	got, ok := GetBadRoot(42)
	if !ok {
		t.Fatal("expected ok=true on first GetBadRoot")
	}
	if got != root {
		t.Fatalf("expected root %v, got %v", root, got)
	}

	// Consume-once: second get must return false.
	_, ok = GetBadRoot(42)
	if ok {
		t.Fatal("expected ok=false on second GetBadRoot (consume-once semantics)")
	}
}

func TestSetGetBadOrder_ConsumeOnce(t *testing.T) {
	SetBadOrder(7, []int{0, 1})

	got, ok := GetBadOrder(7)
	if !ok {
		t.Fatal("expected ok=true on first GetBadOrder")
	}
	if len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("expected [0,1], got %v", got)
	}

	// Consume-once: second get must return false.
	_, ok = GetBadOrder(7)
	if ok {
		t.Fatal("expected ok=false on second GetBadOrder (consume-once semantics)")
	}
}

func TestGetBadRoot_MissingKey(t *testing.T) {
	_, ok := GetBadRoot(99999)
	if ok {
		t.Fatal("expected ok=false for block number with no injected root")
	}
}

func TestGetBadOrder_MissingKey(t *testing.T) {
	_, ok := GetBadOrder(99998)
	if ok {
		t.Fatal("expected ok=false for block number with no injected order")
	}
}

func TestSetBadRoot_Overwrite(t *testing.T) {
	root1 := common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	root2 := common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
	SetBadRoot(100, root1)
	SetBadRoot(100, root2)

	got, ok := GetBadRoot(100)
	if !ok || got != root2 {
		t.Fatalf("expected root2 after overwrite, got %v ok=%v", got, ok)
	}
}

func TestConcurrency_SetGetBadRoot(t *testing.T) {
	const n = 200
	var wg sync.WaitGroup
	for i := uint64(1000); i < 1000+n; i++ {
		wg.Add(1)
		go func(block uint64) {
			defer wg.Done()
			h := common.HexToHash("0xabcd")
			SetBadRoot(block, h)
			GetBadRoot(block)
		}(i)
	}
	wg.Wait()
}

func TestConcurrency_SetGetBadOrder(t *testing.T) {
	const n = 200
	var wg sync.WaitGroup
	for i := uint64(2000); i < 2000+n; i++ {
		wg.Add(1)
		go func(block uint64) {
			defer wg.Done()
			SetBadOrder(block, []int{0, 1})
			GetBadOrder(block)
		}(i)
	}
	wg.Wait()
}
