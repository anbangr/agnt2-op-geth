package types

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// TestFoldTypedReexecRoot_RespondParent verifies the Stage 4 fold: a same-block
// INVOKE+RESPOND pair both fold (the RESPOND's parentOut resolved from InvokeRef),
// while a RESPOND whose parent is NOT in the block is SKIPPED (M6) rather than
// folded with parentOut=0.
func TestFoldTypedReexecRoot_RespondParent(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer := LatestSignerForChainID(big.NewInt(9001))
	wf := common.HexToHash("0x99")

	invoke, err := SignNewTx(key, signer, &InvokeTx{
		ChainID: big.NewInt(9001), Nonce: 0, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
		Gas: 100000, WorkflowId: wf, StepId: 1, AgentRole: "worker", DepInvokeIds: []common.Hash{}, Payload: []byte("call"),
	})
	if err != nil {
		t.Fatal(err)
	}
	respond, err := SignNewTx(key, signer, &RespondTx{
		ChainID: big.NewInt(9001), Nonce: 1, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
		Gas: 100000, WorkflowId: wf, StepId: 2, InvokeRef: invoke.Hash(), ResponsePayload: []byte("resp"), Status: 0,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Same-block: both fold (invoke before respond so the parent resolves).
	rootBoth, countBoth := FoldTypedReexecRoot([]*Transaction{invoke, respond}, signer, nil)
	if countBoth != 2 {
		t.Fatalf("same-block INVOKE+RESPOND: count=%d want 2", countBoth)
	}

	// Only the INVOKE folds when the RESPOND is absent.
	_, countInvoke := FoldTypedReexecRoot([]*Transaction{invoke}, signer, nil)
	if countInvoke != 1 {
		t.Fatalf("INVOKE only: count=%d want 1", countInvoke)
	}

	// M6: a RESPOND whose parent INVOKE is NOT in this block is skipped.
	_, countCross := FoldTypedReexecRoot([]*Transaction{respond}, signer, nil)
	if countCross != 0 {
		t.Fatalf("cross-block RESPOND: count=%d want 0 (skipped, not folded with parentOut=0)", countCross)
	}

	// Determinism.
	rootBoth2, _ := FoldTypedReexecRoot([]*Transaction{invoke, respond}, signer, nil)
	if rootBoth != rootBoth2 {
		t.Fatal("fold not deterministic")
	}
}

// TestFoldTypedReexecRoot_RespondParentMustBeInvoke locks the review fix: opOutput
// stores ONLY INVOKE outputs, so a RESPOND whose InvokeRef points at another
// RESPOND (not an INVOKE) finds no parent and is skipped — the fold self-enforces
// the "parent is an INVOKE" contract instead of relying on the later order check.
func TestFoldTypedReexecRoot_RespondParentMustBeInvoke(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer := LatestSignerForChainID(big.NewInt(9001))
	wf := common.HexToHash("0x99")
	mkR := func(nonce uint64, stepId uint8, ref common.Hash) *Transaction {
		tx, e := SignNewTx(key, signer, &RespondTx{
			ChainID: big.NewInt(9001), Nonce: nonce, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
			Gas: 100000, WorkflowId: wf, StepId: stepId, InvokeRef: ref, ResponsePayload: []byte("r"), Status: 0,
		})
		if e != nil {
			t.Fatal(e)
		}
		return tx
	}
	invoke, err := SignNewTx(key, signer, &InvokeTx{
		ChainID: big.NewInt(9001), Nonce: 0, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
		Gas: 100000, WorkflowId: wf, StepId: 1, AgentRole: "worker", DepInvokeIds: []common.Hash{}, Payload: []byte("c"),
	})
	if err != nil {
		t.Fatal(err)
	}
	respond1 := mkR(1, 2, invoke.Hash())   // parent is the INVOKE -> folds
	respond2 := mkR(2, 3, respond1.Hash()) // parent is a RESPOND -> must be skipped

	_, count := FoldTypedReexecRoot([]*Transaction{invoke, respond1, respond2}, signer, nil)
	if count != 2 {
		t.Fatalf("RESPOND pointing at a RESPOND must be skipped: count=%d want 2 (invoke+respond1)", count)
	}
}
