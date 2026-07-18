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
