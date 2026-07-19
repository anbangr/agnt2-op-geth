package types

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Stage 5 COMPOSE fold tests: a COMPOSE(W) folds with childOutputHashes = the
// block-ordered committed outputs of THIS block's folded same-workflow steps
// (INVOKE + RESPOND); zero in-block constituents => the COMPOSE is SKIPPED
// (mirroring the Solidity COMPOSE_EMPTY_TREE stance — no vacuous empty-child
// leaf); COMPOSE outputs are never children nor RESPOND parents.

func composeFoldTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mkFoldInvoke(t *testing.T, signer Signer, key *ecdsa.PrivateKey, nonce uint64, wf common.Hash, payload []byte) *Transaction {
	t.Helper()
	tx, err := SignNewTx(key, signer, &InvokeTx{
		ChainID: big.NewInt(9001), Nonce: nonce, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
		Gas: 100000, WorkflowId: wf, StepId: uint8(nonce + 1), AgentRole: "worker", DepInvokeIds: []common.Hash{}, Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func mkFoldRespond(t *testing.T, signer Signer, key *ecdsa.PrivateKey, nonce uint64, wf common.Hash, ref common.Hash) *Transaction {
	t.Helper()
	tx, err := SignNewTx(key, signer, &RespondTx{
		ChainID: big.NewInt(9001), Nonce: nonce, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
		Gas: 100000, WorkflowId: wf, StepId: uint8(nonce + 1), InvokeRef: ref, ResponsePayload: []byte("resp"), Status: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func mkFoldCompose(t *testing.T, signer Signer, key *ecdsa.PrivateKey, nonce uint64, wf common.Hash) *Transaction {
	t.Helper()
	tx, err := SignNewTx(key, signer, &ComposeTypedTx{
		ChainID: big.NewInt(9001), Nonce: nonce, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(2e10),
		Gas: 200000, WorkflowId: wf, StepCount: 2,
		StepWorkflowRoots: []common.Hash{common.HexToHash("0x0a"), common.HexToHash("0x0b")},
		Payouts:           []*big.Int{big.NewInt(1), big.NewInt(2)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// TestFoldTypedReexecRoot_ComposeChildBinding: INVOKE(W) + RESPOND(W) + COMPOSE(W)
// => 3 leaves, and the COMPOSE leaf is EXACTLY the leaf derived from the ordered
// [invokeOut, respondOut] child set (recomputed independently here) — locking both
// the child sourcing rule and the envelope/derive encodings.
func TestFoldTypedReexecRoot_ComposeChildBinding(t *testing.T) {
	key := composeFoldTestKey(t)
	signer := LatestSignerForChainID(big.NewInt(9001))
	wf := common.HexToHash("0xC0")

	invoke := mkFoldInvoke(t, signer, key, 0, wf, []byte("call"))
	respond := mkFoldRespond(t, signer, key, 1, wf, invoke.Hash())
	compose := mkFoldCompose(t, signer, key, 2, wf)
	agent, err := Sender(signer, compose)
	if err != nil {
		t.Fatal(err)
	}

	root, count := FoldTypedReexecRoot([]*Transaction{invoke, respond, compose}, signer, nil)
	if count != 3 {
		t.Fatalf("count=%d want 3 (invoke+respond+compose)", count)
	}

	// Independently recompute all three leaves and fold — must equal the fold's root.
	invokeOut := agnt2DeriveInvokeOutputHash(wf, agent, invoke.Data(), []byte{})
	invokeLeaf := agnt2ReexecLeaf(invoke.Hash(), agnt2StepTypeInvoke, wf, agent, agnt2InvokeEnvelope(invoke.Data(), []byte{}), invokeOut)
	respondOut := agnt2DeriveRespondOutputHash(wf, agent, invokeOut, []byte{}, respond.Data())
	respondLeaf := agnt2ReexecLeaf(respond.Hash(), agnt2StepTypeRespond, wf, agent, agnt2RespondEnvelope([]byte{}, respond.Data(), invokeOut), respondOut)
	children := [][32]byte{invokeOut, respondOut} // block order: INVOKE then RESPOND
	composeOut := agnt2DeriveComposeOutputHash(wf, agent, []byte{}, children, []byte{})
	composeLeaf := agnt2ReexecLeaf(compose.Hash(), agnt2StepTypeCompose, wf, agent, agnt2ComposeEnvelope([]byte{}, []byte{}, children), composeOut)

	wantRoot := foldMMR([][32]byte{invokeLeaf, respondLeaf, composeLeaf})
	if root != wantRoot {
		t.Fatalf("fold root mismatch:\n got %x\nwant %x", root, wantRoot)
	}

	// Determinism.
	root2, _ := FoldTypedReexecRoot([]*Transaction{invoke, respond, compose}, signer, nil)
	if root != root2 {
		t.Fatal("fold not deterministic")
	}
}

// TestFoldTypedReexecRoot_ComposeEmptyChildrenSkipped: a COMPOSE with no in-block
// same-workflow steps folds NOTHING — neither alone nor when another workflow has
// steps in the block.
func TestFoldTypedReexecRoot_ComposeEmptyChildrenSkipped(t *testing.T) {
	key := composeFoldTestKey(t)
	signer := LatestSignerForChainID(big.NewInt(9001))
	wfA := common.HexToHash("0xAA")
	wfB := common.HexToHash("0xBB")

	composeB := mkFoldCompose(t, signer, key, 0, wfB)
	if _, count := FoldTypedReexecRoot([]*Transaction{composeB}, signer, nil); count != 0 {
		t.Fatalf("lone COMPOSE: count=%d want 0 (empty-children skip)", count)
	}

	// Steps exist only for workflow A: COMPOSE(B) still skips, INVOKE(A) still folds.
	invokeA := mkFoldInvoke(t, signer, key, 1, wfA, []byte("call"))
	composeB2 := mkFoldCompose(t, signer, key, 2, wfB)
	if _, count := FoldTypedReexecRoot([]*Transaction{invokeA, composeB2}, signer, nil); count != 1 {
		t.Fatalf("cross-workflow: count=%d want 1 (invoke only; COMPOSE(B) has no children)", count)
	}
}

// TestFoldTypedReexecRoot_ComposeNotChildNorParent: a COMPOSE's output is neither a
// later COMPOSE's child (children are steps only) nor a RESPOND's parent (opOutput
// stores INVOKE only) — two COMPOSE(W) leaves bind the IDENTICAL child set, and a
// RESPOND pointing at a COMPOSE hash is skipped.
func TestFoldTypedReexecRoot_ComposeNotChildNorParent(t *testing.T) {
	key := composeFoldTestKey(t)
	signer := LatestSignerForChainID(big.NewInt(9001))
	wf := common.HexToHash("0xC1")

	invoke := mkFoldInvoke(t, signer, key, 0, wf, []byte("call"))
	compose1 := mkFoldCompose(t, signer, key, 1, wf)
	compose2 := mkFoldCompose(t, signer, key, 2, wf)
	agent, err := Sender(signer, compose1)
	if err != nil {
		t.Fatal(err)
	}

	_, count := FoldTypedReexecRoot([]*Transaction{invoke, compose1, compose2}, signer, nil)
	if count != 3 {
		t.Fatalf("count=%d want 3 (invoke + two composes)", count)
	}
	// Both COMPOSE leaves must derive from the SAME single-child set [invokeOut] —
	// if compose1's output leaked into wfOutputs, compose2's derivation would differ.
	invokeOut := agnt2DeriveInvokeOutputHash(wf, agent, invoke.Data(), []byte{})
	children := [][32]byte{invokeOut}
	c1 := agnt2DeriveComposeOutputHash(wf, agent, []byte{}, children, []byte{})
	c2 := agnt2DeriveComposeOutputHash(wf, agent, []byte{}, children, []byte{})
	if c1 != c2 {
		t.Fatal("sanity: identical child sets must derive identical outputs")
	}
	invokeLeaf := agnt2ReexecLeaf(invoke.Hash(), agnt2StepTypeInvoke, wf, agent, agnt2InvokeEnvelope(invoke.Data(), []byte{}), invokeOut)
	l1 := agnt2ReexecLeaf(compose1.Hash(), agnt2StepTypeCompose, wf, agent, agnt2ComposeEnvelope([]byte{}, []byte{}, children), c1)
	l2 := agnt2ReexecLeaf(compose2.Hash(), agnt2StepTypeCompose, wf, agent, agnt2ComposeEnvelope([]byte{}, []byte{}, children), c2)
	wantRoot := foldMMR([][32]byte{invokeLeaf, l1, l2})
	gotRoot, _ := FoldTypedReexecRoot([]*Transaction{invoke, compose1, compose2}, signer, nil)
	if gotRoot != wantRoot {
		t.Fatalf("two-COMPOSE root mismatch (compose output leaked into children?):\n got %x\nwant %x", gotRoot, wantRoot)
	}

	// A RESPOND whose InvokeRef points at a COMPOSE is skipped (type confusion guard).
	respondAtCompose := mkFoldRespond(t, signer, key, 3, wf, compose1.Hash())
	_, count2 := FoldTypedReexecRoot([]*Transaction{invoke, compose1, respondAtCompose}, signer, nil)
	if count2 != 2 {
		t.Fatalf("RESPOND->COMPOSE ref: count=%d want 2 (invoke + compose; respond skipped)", count2)
	}
}

// TestFoldTypedReexecRoot_ComposeChildFromResolver locks the Stage 4/5 seam with
// an EXACT recompute: a RESPOND whose parent resolves via the resolver (the
// cross-block path) folds, and its committed output — derived from the RESOLVED
// parentOut — is the COMPOSE's child. The stub resolver stands in for the state
// ring (whose behavior is proven in core/agnt2store); what is locked here is the
// derivation chain resolver -> respondOut -> children -> composeOut, leaf by leaf.
func TestFoldTypedReexecRoot_ComposeChildFromResolver(t *testing.T) {
	key := composeFoldTestKey(t)
	signer := LatestSignerForChainID(big.NewInt(9001))
	wf := common.HexToHash("0xC7")

	// The parent INVOKE lives in a "prior block": only its hash + output exist here.
	parentRef := common.HexToHash("0x1111")
	parentOut := common.HexToHash("0x2222")
	resolver := func(ref common.Hash) (common.Hash, bool) {
		if ref == parentRef {
			return parentOut, true
		}
		return common.Hash{}, false
	}

	respond := mkFoldRespond(t, signer, key, 0, wf, parentRef)
	compose := mkFoldCompose(t, signer, key, 1, wf)
	agent, err := Sender(signer, respond)
	if err != nil {
		t.Fatal(err)
	}

	root, count := FoldTypedReexecRoot([]*Transaction{respond, compose}, signer, resolver)
	if count != 2 {
		t.Fatalf("count=%d want 2 (resolver-resolved respond + compose)", count)
	}

	respondOut := agnt2DeriveRespondOutputHash(wf, agent, parentOut, []byte{}, respond.Data())
	respondLeaf := agnt2ReexecLeaf(respond.Hash(), agnt2StepTypeRespond, wf, agent, agnt2RespondEnvelope([]byte{}, respond.Data(), parentOut), respondOut)
	children := [][32]byte{respondOut}
	composeOut := agnt2DeriveComposeOutputHash(wf, agent, []byte{}, children, []byte{})
	composeLeaf := agnt2ReexecLeaf(compose.Hash(), agnt2StepTypeCompose, wf, agent, agnt2ComposeEnvelope([]byte{}, []byte{}, children), composeOut)
	if want := foldMMR([][32]byte{respondLeaf, composeLeaf}); root != want {
		t.Fatalf("resolver->respond->compose chain mismatch:\n got %x\nwant %x", root, want)
	}

	// Without the resolver both skip (respond: unresolved parent; compose: no children).
	if _, c := FoldTypedReexecRoot([]*Transaction{respond, compose}, signer, nil); c != 0 {
		t.Fatalf("nil resolver: count=%d want 0", c)
	}
}
