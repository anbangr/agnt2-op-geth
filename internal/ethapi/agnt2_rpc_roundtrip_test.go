package ethapi

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// TestAgnt2TypedTxRPCRoundTrip exercises the exact server->client path that
// stalls op-node: newRPCTransaction (op-geth RPC marshaller) -> JSON ->
// types.Transaction.UnmarshalJSON (op-node's decoder). The reconstructed tx must
// have the SAME hash, or op-node fails to re-encode the parent block's txs.
func TestAgnt2TypedTxRPCRoundTrip(t *testing.T) {
	b := func(x int64) *big.Int { return big.NewInt(x) }
	cases := []types.TxData{
		&types.InvokeTx{ChainID: b(9001), Nonce: 7, GasTipCap: b(1_000_000_000), GasFeeCap: b(20_000_000_000), Gas: 500000,
			WorkflowId: common.HexToHash("0x11"), StepId: 1, AgentRole: "worker",
			DepInvokeIds: []common.Hash{common.HexToHash("0xaa"), common.HexToHash("0xbb")}, Payload: []byte{1, 2, 3}, V: b(1), R: b(0x1234), S: b(0x5678)},
		&types.RespondTx{ChainID: b(9001), Nonce: 3, GasTipCap: b(1_000_000_000), GasFeeCap: b(20_000_000_000), Gas: 300000,
			WorkflowId: common.HexToHash("0x22"), StepId: 2, InvokeRef: common.HexToHash("0xcc"),
			ResponsePayload: []byte{0x0a, 0x0b}, Status: 1, V: b(0), R: b(0x99), S: b(0x88)},
		&types.ComposeTypedTx{ChainID: b(9001), Nonce: 5, GasTipCap: b(1_000_000_000), GasFeeCap: b(20_000_000_000), Gas: 400000,
			WorkflowId: common.HexToHash("0x33"), StepCount: 2, StepWorkflowRoots: []common.Hash{common.HexToHash("0xd1"), common.HexToHash("0xd2")},
			Payouts: []*big.Int{b(100), b(200)}, V: b(1), R: b(0x77), S: b(0x66)},
	}
	cfg := params.AllDevChainProtocolChanges
	for i, inner := range cases {
		orig := types.NewTx(inner)
		rpcTx := newRPCTransaction(orig, common.Hash{}, 0, 0, 0, nil, cfg, nil)
		js, err := json.Marshal(rpcTx)
		if err != nil {
			t.Fatalf("case %d (%T): marshal: %v", i, inner, err)
		}
		var dec types.Transaction
		if err := dec.UnmarshalJSON(js); err != nil {
			t.Fatalf("case %d (%T): unmarshal: %v; json=%s", i, inner, err, js)
		}
		if dec.Type() != orig.Type() {
			t.Fatalf("case %d (%T): type %d != %d", i, inner, dec.Type(), orig.Type())
		}
		if dec.Hash() != orig.Hash() {
			t.Fatalf("case %d (%T): hash %s != %s; json=%s", i, inner, dec.Hash(), orig.Hash(), js)
		}
	}
}
