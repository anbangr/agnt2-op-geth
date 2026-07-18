// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// B2' typed-op re-execution commitment. Folds a per-op re-exec MMR
// (TypedReexecRoot) over the block's typed ops so the L1 LayerRootSettlement
// fraud gate can prove a committed op's outputHash and slash iff it diverges
// from the canonical re-derivation. The leaf/derivation encodings here are
// byte-identical to the Solidity side (AGNT2StepVerifier.reexecFraudLeaf /
// TypedVmReexec.deriveInvoke) — locked by golden/typed-reexec/reexec-vectors.json
// (must-fix M3: any divergence re-opens the C0b honest-deposit drain).
//
// Stage 2 scope: INVOKE only (responseBytes empty; taskId := WorkflowId). The
// committed outputHash is RE-DERIVED here, so a consensus-valid block's INVOKE
// leaf always has committed == canonical (INVOKE is vacuous by design — Stage 1
// closed the drain; RESPOND/COMPOSE add the real fraud teeth in later stages).

package types

import (
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const agnt2StepTypeInvoke uint8 = 1

// ABI types for the re-exec encodings. Constructed once; abi.NewType for these
// primitives never errors.
var (
	agnt2Bytes32Ty, _ = abi.NewType("bytes32", "", nil)
	agnt2Uint8Ty, _   = abi.NewType("uint8", "", nil)
	agnt2AddressTy, _ = abi.NewType("address", "", nil)
	agnt2BytesTy, _   = abi.NewType("bytes", "", nil)

	// abi.encode(bytes callData, bytes responseBytes)
	agnt2EnvelopeArgs = abi.Arguments{{Type: agnt2BytesTy}, {Type: agnt2BytesTy}}
	// abi.encode(bytes32 taskId, address agent, bytes callData)
	agnt2InputCommitArgs = abi.Arguments{{Type: agnt2Bytes32Ty}, {Type: agnt2AddressTy}, {Type: agnt2BytesTy}}
	// abi.encode(bytes32 inputCommitment, bytes responseBytes)
	agnt2OutputArgs = abi.Arguments{{Type: agnt2Bytes32Ty}, {Type: agnt2BytesTy}}
	// abi.encode(bytes32 txHash, uint8 stepType, bytes32 taskId, address agent, bytes stepPayload, bytes32 committedOutputHash)
	agnt2LeafArgs = abi.Arguments{
		{Type: agnt2Bytes32Ty}, {Type: agnt2Uint8Ty}, {Type: agnt2Bytes32Ty},
		{Type: agnt2AddressTy}, {Type: agnt2BytesTy}, {Type: agnt2Bytes32Ty},
	}
)

// agnt2InvokeEnvelope returns abi.encode(callData, responseBytes) — the INVOKE
// stepPayload envelope (byte-identical to Solidity _invokeEnvelope).
func agnt2InvokeEnvelope(callData, responseBytes []byte) []byte {
	out, err := agnt2EnvelopeArgs.Pack(callData, responseBytes)
	if err != nil {
		panic(err) // fixed types + arbitrary bytes never fail to pack
	}
	return out
}

// agnt2DeriveInvokeOutputHash mirrors TypedVmReexec.deriveInvoke:
// inputCommitment = keccak(abi.encode(taskId, agent, callData));
// outputHash      = keccak(abi.encode(inputCommitment, responseBytes)).
func agnt2DeriveInvokeOutputHash(taskId common.Hash, agent common.Address, callData, responseBytes []byte) common.Hash {
	ic, err := agnt2InputCommitArgs.Pack([32]byte(taskId), agent, callData)
	if err != nil {
		panic(err)
	}
	inputCommitment := crypto.Keccak256Hash(ic)
	oh, err := agnt2OutputArgs.Pack([32]byte(inputCommitment), responseBytes)
	if err != nil {
		panic(err)
	}
	return crypto.Keccak256Hash(oh)
}

// agnt2ReexecLeaf mirrors AGNT2StepVerifier.reexecFraudLeaf.
func agnt2ReexecLeaf(txHash common.Hash, stepType uint8, taskId common.Hash, agent common.Address, stepPayload []byte, committedOutputHash common.Hash) common.Hash {
	packed, err := agnt2LeafArgs.Pack([32]byte(txHash), stepType, [32]byte(taskId), agent, stepPayload, [32]byte(committedOutputHash))
	if err != nil {
		panic(err)
	}
	return crypto.Keccak256Hash(packed)
}

// FoldTypedReexecRoot computes the per-op re-exec MMR root + leaf count over the
// block's INVOKE typed ops, in block order (matching FoldTypedOpRoot's ordering).
// The committed outputHash is re-derived here, so it equals the canonical value
// for every honest op. Returns the empty-MMR root + 0 when no INVOKE ops present.
func FoldTypedReexecRoot(txs []*Transaction, signer Signer) (common.Hash, uint64) {
	var leaves [][32]byte
	for _, tx := range txs {
		if tx.Type() != InvokeTxType {
			continue
		}
		opId, ok := tx.Agnt2OperationID()
		if !ok {
			continue
		}
		agent, err := Sender(signer, tx)
		if err != nil {
			// An INVOKE whose signer cannot be recovered cannot be folded; skip it
			// (it would also fail admission). Consistent producer/validator behavior.
			continue
		}
		taskId := opId.WorkflowId
		callData := tx.Data()      // InvokeTx.Payload
		responseBytes := []byte{}  // INVOKE: request-only (Stage 2 convention)
		committed := agnt2DeriveInvokeOutputHash(taskId, agent, callData, responseBytes)
		leaf := agnt2ReexecLeaf(tx.Hash(), agnt2StepTypeInvoke, taskId, agent, agnt2InvokeEnvelope(callData, responseBytes), committed)
		leaves = append(leaves, leaf)
	}
	return foldMMR(leaves), uint64(len(leaves))
}
