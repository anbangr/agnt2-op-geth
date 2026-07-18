package types

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// TestAgnt2TypedTxJSONRoundTrip verifies the AGNT2 typed txs (0x7A/0x7B/0x7C)
// round-trip through JSON (Marshal -> Unmarshal) with an IDENTICAL hash and
// binary encoding. This is the property op-node relies on when it retrieves a
// parent L2 block containing typed txs over JSON-RPC to build the next payload.
func TestAgnt2TypedTxJSONRoundTrip(t *testing.T) {
	b := func(x int64) *big.Int { return big.NewInt(x) }
	cases := []TxData{
		&InvokeTx{
			ChainID: b(9001), Nonce: 7, GasTipCap: b(1_000_000_000), GasFeeCap: b(20_000_000_000), Gas: 500000,
			WorkflowId: common.HexToHash("0x11"), StepId: 1, AgentRole: "worker",
			DepInvokeIds: []common.Hash{common.HexToHash("0xaa"), common.HexToHash("0xbb")},
			Payload:      []byte{0x01, 0x02, 0x03}, V: b(1), R: b(0x1234), S: b(0x5678),
		},
		// InvokeTx with empty dep list + empty payload (omitempty edge case)
		&InvokeTx{
			ChainID: b(9001), Nonce: 0, GasTipCap: b(1_000_000_000), GasFeeCap: b(20_000_000_000), Gas: 500000,
			WorkflowId: common.HexToHash("0x12"), StepId: 1, AgentRole: "worker",
			DepInvokeIds: []common.Hash{}, Payload: []byte{}, V: b(0), R: b(0x11), S: b(0x22),
		},
		&RespondTx{
			ChainID: b(9001), Nonce: 3, GasTipCap: b(1_000_000_000), GasFeeCap: b(20_000_000_000), Gas: 300000,
			WorkflowId: common.HexToHash("0x22"), StepId: 2, InvokeRef: common.HexToHash("0xcc"),
			ResponsePayload: []byte{0x0a, 0x0b}, Status: 1, V: b(0), R: b(0x99), S: b(0x88),
		},
		&ComposeTypedTx{
			ChainID: b(9001), Nonce: 5, GasTipCap: b(1_000_000_000), GasFeeCap: b(20_000_000_000), Gas: 400000,
			WorkflowId: common.HexToHash("0x33"), StepCount: 2,
			StepWorkflowRoots: []common.Hash{common.HexToHash("0xd1"), common.HexToHash("0xd2")},
			Payouts:           []*big.Int{b(100), b(200)}, V: b(1), R: b(0x77), S: b(0x66),
		},
	}
	for i, inner := range cases {
		orig := NewTx(inner)
		js, err := orig.MarshalJSON()
		if err != nil {
			t.Fatalf("case %d (%T): marshal: %v", i, inner, err)
		}
		var dec Transaction
		if err := dec.UnmarshalJSON(js); err != nil {
			t.Fatalf("case %d (%T): unmarshal: %v; json=%s", i, inner, err, js)
		}
		if dec.Type() != orig.Type() {
			t.Fatalf("case %d (%T): type %d != %d", i, inner, dec.Type(), orig.Type())
		}
		if dec.Hash() != orig.Hash() {
			t.Fatalf("case %d (%T): hash %s != %s; json=%s", i, inner, dec.Hash(), orig.Hash(), js)
		}
		ob, err1 := orig.MarshalBinary()
		db, err2 := dec.MarshalBinary()
		if err1 != nil || err2 != nil {
			t.Fatalf("case %d (%T): binary err %v / %v", i, inner, err1, err2)
		}
		if !bytes.Equal(ob, db) {
			t.Fatalf("case %d (%T): binary mismatch", i, inner)
		}
	}
}
