package types

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// TestHeaderRLP_TypedReexecRoundTrip verifies the new trailing optional header
// pair round-trips through RLP and is bound in the header hash. A realistic
// post-Isthmus header (all earlier optionals set) is used — a MINIMAL header that
// leaves earlier optionals nil while setting a late one cannot round-trip fixed-size
// *common.Hash fields, which is pre-existing behavior identical for TypedOpRoot.
func TestHeaderRLP_TypedReexecRoundTrip(t *testing.T) {
	hh := common.HexToHash("0xaa")
	u := uint64(7)
	root := common.HexToHash("0xb4f1397ea948c51180ecb4c2bcc3dc9ee2b00dc9aa3b73263fb6d4ba6f60a17d")
	count := uint64(3)
	h := &Header{
		Number:           big.NewInt(1),
		BaseFee:          big.NewInt(1),
		WithdrawalsHash:  &hh,
		BlobGasUsed:      &u,
		ExcessBlobGas:    &u,
		ParentBeaconRoot: &hh,
		RequestsHash:     &hh,
		SlotNumber:       &u,
		InteractionRoot:  &hh,
		InteractionCount: &u,
		TypedOpRoot:      &hh,
		TypedOpCount:     &u,
		TypedReexecRoot:  &root,
		TypedReexecCount: &count,
	}

	enc, err := rlp.EncodeToBytes(h)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var dec Header
	if err := rlp.DecodeBytes(enc, &dec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.TypedReexecRoot == nil || *dec.TypedReexecRoot != root {
		t.Fatalf("root round-trip: got %v want %s", dec.TypedReexecRoot, root.Hex())
	}
	if dec.TypedReexecCount == nil || *dec.TypedReexecCount != count {
		t.Fatalf("count round-trip: got %v want %d", dec.TypedReexecCount, count)
	}
	if dec.Hash() != h.Hash() {
		t.Fatalf("hash not stable across RLP round-trip")
	}

	// Backward compat: a header with the reexec fields nil re-decodes them as nil.
	h.TypedReexecRoot = nil
	h.TypedReexecCount = nil
	encBare, _ := rlp.EncodeToBytes(h)
	var decBare Header
	if err := rlp.DecodeBytes(encBare, &decBare); err != nil {
		t.Fatalf("decode bare: %v", err)
	}
	if decBare.TypedReexecRoot != nil || decBare.TypedReexecCount != nil {
		t.Fatal("bare header decoded non-nil reexec fields")
	}
}
