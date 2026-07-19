package types

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// TestReexecLeaf_GoldenCrossLang locks the Go re-exec encodings byte-identical to
// the Solidity side via golden/typed-reexec/reexec-vectors.json (must-fix M3).
// Divergence between Go (FoldTypedReexecRoot) and Solidity (reexecFraudLeaf /
// deriveInvoke) would re-open the C0b honest-deposit drain.
func TestReexecLeaf_GoldenCrossLang(t *testing.T) {
	taskId := crypto.Keccak256Hash([]byte("golden-workflow"))
	agent := common.HexToAddress("0x00000000000000000000000000000000caFe0001")
	txHash := crypto.Keccak256Hash([]byte("golden-tx"))
	callData := []byte("golden-call")
	responseBytes := []byte{}

	const (
		wantCommitted = "0x9499c1314d355d7c7625584bcea66d563b413dfadd1ea0cfe31898bba9248ee3"
		wantLeaf      = "0xabafa492cfbaf46790f5efe787500e2d9c831bbc848fcc276a4739ff6bfaf829"
		wantRoot3     = "0xb4f1397ea948c51180ecb4c2bcc3dc9ee2b00dc9aa3b73263fb6d4ba6f60a17d"
	)

	env := agnt2InvokeEnvelope(callData, responseBytes)
	committed := agnt2DeriveInvokeOutputHash(taskId, agent, callData, responseBytes)
	if committed.Hex() != wantCommitted {
		t.Fatalf("committedOutputHash drift: got=%s want=%s", committed.Hex(), wantCommitted)
	}

	leaf := agnt2ReexecLeaf(txHash, agnt2StepTypeInvoke, taskId, agent, env, committed)
	if leaf.Hex() != wantLeaf {
		t.Fatalf("reexecLeaf drift: got=%s want=%s", leaf.Hex(), wantLeaf)
	}

	// 3-op fold root (golden op + two honest ops).
	mkLeaf := func(txSeed, cd string) [32]byte {
		th := crypto.Keccak256Hash([]byte(txSeed))
		c := agnt2DeriveInvokeOutputHash(taskId, agent, []byte(cd), responseBytes)
		l := agnt2ReexecLeaf(th, agnt2StepTypeInvoke, taskId, agent, agnt2InvokeEnvelope([]byte(cd), responseBytes), c)
		return [32]byte(l)
	}
	leaves := [][32]byte{mkLeaf("golden-tx", "golden-call"), mkLeaf("g1", "c1"), mkLeaf("g2", "c2")}
	if root := foldMMR(leaves); root.Hex() != wantRoot3 {
		t.Fatalf("reexec root drift: got=%s want=%s", root.Hex(), wantRoot3)
	}
}

// TestReexecRespondLeaf_GoldenCrossLang locks the Go RESPOND encoding byte-identical
// to Solidity (deriveRespond + reexecFraudLeaf). The RESPOND chains to the INVOKE
// golden: parentOut == the INVOKE golden committedOutputHash. This is where the
// fraud gate gets real teeth (the parent anchor).
func TestReexecRespondLeaf_GoldenCrossLang(t *testing.T) {
	taskId := crypto.Keccak256Hash([]byte("golden-workflow"))
	agent := common.HexToAddress("0x00000000000000000000000000000000caFe0001")
	txHash := crypto.Keccak256Hash([]byte("respond-golden-tx"))
	parentOut := common.HexToHash("0x9499c1314d355d7c7625584bcea66d563b413dfadd1ea0cfe31898bba9248ee3")
	callData := []byte{}
	responseBytes := []byte("respond-payload")

	const (
		wantCommitted = "0xcd4c447aa0fcdb83c12eeba3b99139ad67cf8c8ca7eea30e3bc12ef7a4088138"
		wantLeaf      = "0x8b659b38fc14f0231ee568a950fa08942dec30c0ea129c3a65c1a3e174dafabf"
	)

	committed := agnt2DeriveRespondOutputHash(taskId, agent, parentOut, callData, responseBytes)
	if committed.Hex() != wantCommitted {
		t.Fatalf("RESPOND committedOutputHash drift: got=%s want=%s", committed.Hex(), wantCommitted)
	}
	leaf := agnt2ReexecLeaf(txHash, agnt2StepTypeRespond, taskId, agent, agnt2RespondEnvelope(callData, responseBytes, parentOut), committed)
	if leaf.Hex() != wantLeaf {
		t.Fatalf("RESPOND reexecLeaf drift: got=%s want=%s", leaf.Hex(), wantLeaf)
	}
}

// TestReexecComposeLeaf_GoldenCrossLang locks the Go COMPOSE encoding byte-identical
// to Solidity (deriveCompose + reexecFraudLeaf). The children chain to BOTH prior
// goldens — [INVOKE golden committed, RESPOND golden committed] in block order —
// exactly the fold's child-sourcing rule. The ordered child binding is where the
// COMPOSE gate gets teeth (a re-pointed/reordered child set diverges committed).
func TestReexecComposeLeaf_GoldenCrossLang(t *testing.T) {
	taskId := crypto.Keccak256Hash([]byte("golden-workflow"))
	agent := common.HexToAddress("0x00000000000000000000000000000000caFe0001")
	txHash := crypto.Keccak256Hash([]byte("compose-golden-tx"))
	children := [][32]byte{
		common.HexToHash("0x9499c1314d355d7c7625584bcea66d563b413dfadd1ea0cfe31898bba9248ee3"), // INVOKE golden committed
		common.HexToHash("0xcd4c447aa0fcdb83c12eeba3b99139ad67cf8c8ca7eea30e3bc12ef7a4088138"), // RESPOND golden committed
	}
	callData := []byte{}
	responseBytes := []byte{}

	const (
		wantCommitted = "0x70e679dd8d054c43a332a6c35ed67ec0cf54772fa619401464015d2603da2c9a"
		wantLeaf      = "0xe719b58c85d3614ae77382d1abcc831d42df3c0bd3de97934014ed68a7e6e893"
	)

	committed := agnt2DeriveComposeOutputHash(taskId, agent, callData, children, responseBytes)
	if committed.Hex() != wantCommitted {
		t.Fatalf("COMPOSE committedOutputHash drift: got=%s want=%s", committed.Hex(), wantCommitted)
	}
	leaf := agnt2ReexecLeaf(txHash, agnt2StepTypeCompose, taskId, agent, agnt2ComposeEnvelope(callData, responseBytes, children), committed)
	if leaf.Hex() != wantLeaf {
		t.Fatalf("COMPOSE reexecLeaf drift: got=%s want=%s", leaf.Hex(), wantLeaf)
	}

	// Reordered children must diverge (the ordered-tree binding).
	swapped := [][32]byte{children[1], children[0]}
	if agnt2DeriveComposeOutputHash(taskId, agent, callData, swapped, responseBytes) == committed {
		t.Fatal("reordered children must diverge committed hash")
	}
}
