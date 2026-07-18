package ethapi

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// TestRPCMarshalHeaderAgnt2RoundTrip verifies that RPCMarshalHeader emits every
// consensus header field so that a client fetching the block over JSON-RPC and
// decoding it back to a types.Header recovers the IDENTICAL hash. Missing any of
// them (typedOpRoot/typedOpCount were absent) makes the block JSON lossy and stalls
// op-node/op-batcher block-lineage tracking with ErrReorg on blocks with typed ops.
func TestRPCMarshalHeaderAgnt2RoundTrip(t *testing.T) {
	u := func(x uint64) *uint64 { return &x }
	ir := common.HexToHash("0x593744410000000000000000000000000000000000000000000000000000dead")
	tor := common.HexToHash("0xabcdef0000000000000000000000000000000000000000000000000000000042")
	trr := common.HexToHash("0xb4f1397ea948c51180ecb4c2bcc3dc9ee2b00dc9aa3b73263fb6d4ba6f60a17d")
	for _, withTypedOp := range []bool{false, true} {
		h := &types.Header{
			ParentHash:  common.HexToHash("0x01"),
			UncleHash:   types.EmptyUncleHash,
			Root:        common.HexToHash("0x02"),
			TxHash:      common.HexToHash("0x03"),
			ReceiptHash: common.HexToHash("0x04"),
			Number:      big.NewInt(90),
			GasLimit:    60_000_000,
			GasUsed:     59_500_000,
			Time:        1784000000,
			Difficulty:  big.NewInt(0),
			BaseFee:     big.NewInt(1_000_000_000),
			SlotNumber:  u(0),
			// AGNT2 typed-consensus fields
			InteractionRoot:  &ir,
			InteractionCount: u(401),
		}
		if withTypedOp {
			h.TypedOpRoot = &tor
			h.TypedOpCount = u(5)
			// B2' Stage 2/3: the reexec pair co-occurs with typedOp and must also
			// survive the RPC JSON round-trip (else the sidecar can't read the
			// consensus-committed reexec root and the header re-hash drifts).
			h.TypedReexecRoot = &trr
			h.TypedReexecCount = u(3)
		}
		ref := h.Hash()
		js, err := json.Marshal(RPCMarshalHeader(h))
		if err != nil {
			t.Fatalf("withTypedOp=%v marshal: %v", withTypedOp, err)
		}
		var got types.Header
		if err := got.UnmarshalJSON(js); err != nil {
			t.Fatalf("withTypedOp=%v unmarshal: %v; json=%s", withTypedOp, err, js)
		}
		if got.Hash() != ref {
			t.Fatalf("withTypedOp=%v: reconstructed hash %s != real %s; json=%s", withTypedOp, got.Hash(), ref, js)
		}
	}
}
