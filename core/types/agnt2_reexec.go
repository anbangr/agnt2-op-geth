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

const (
	agnt2StepTypeInvoke  uint8 = 1
	agnt2StepTypeRespond uint8 = 2
)

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
	// abi.encode(bytes callData, bytes responseBytes, bytes32 parentOut) — RESPOND envelope
	agnt2RespondEnvelopeArgs = abi.Arguments{{Type: agnt2BytesTy}, {Type: agnt2BytesTy}, {Type: agnt2Bytes32Ty}}
	// abi.encode(bytes32 taskId, address agent, bytes32 parentInvokeOutputHash, bytes callData)
	agnt2RespondInputCommitArgs = abi.Arguments{{Type: agnt2Bytes32Ty}, {Type: agnt2AddressTy}, {Type: agnt2Bytes32Ty}, {Type: agnt2BytesTy}}
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

// agnt2RespondEnvelope returns abi.encode(callData, responseBytes, parentOut) —
// the RESPOND stepPayload envelope (byte-identical to the Solidity RESPOND path).
func agnt2RespondEnvelope(callData, responseBytes []byte, parentOut common.Hash) []byte {
	out, err := agnt2RespondEnvelopeArgs.Pack(callData, responseBytes, [32]byte(parentOut))
	if err != nil {
		panic(err)
	}
	return out
}

// agnt2DeriveRespondOutputHash mirrors TypedVmReexec.deriveRespond: the parent
// INVOKE's outputHash is bound into the commitment preimage so a RESPOND cannot be
// re-pointed at a different (or forged) parent — this is where the fraud gate gets
// real teeth (INVOKE alone is vacuous).
func agnt2DeriveRespondOutputHash(taskId common.Hash, agent common.Address, parentOut common.Hash, callData, responseBytes []byte) common.Hash {
	ic, err := agnt2RespondInputCommitArgs.Pack([32]byte(taskId), agent, [32]byte(parentOut), callData)
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

// ReexecParentResolver resolves a RESPOND's parent INVOKE committedOutputHash from
// a STRICTLY-PRIOR block's committed state (the B2' cross-block ring). Returns
// (hash, true) on a cross-block hit; (zero, false) when the parent is absent,
// evicted past the window, or in the CURRENT block (same-block parents are served
// only by the in-block map). nil => same-block-only fold (pre-cross-block behavior;
// preserves existing golden vectors + tests).
type ReexecParentResolver func(invokeRef common.Hash) (common.Hash, bool)

// AGNT2InvokeReexecOutput is the SINGLE SOURCE OF TRUTH for an INVOKE's committed
// re-exec outputHash: deriveInvoke(taskId=WorkflowId, agent=signer, callData=Payload,
// responseBytes=empty). ok is false for a non-INVOKE or an unrecoverable signer.
// Used by BOTH the fold INVOKE branch AND the cross-block store write hook, so the
// value written to state is byte-identical to the same-block map value — any skew
// between the two would diverge the fold (chain split).
func AGNT2InvokeReexecOutput(tx *Transaction, signer Signer) (common.Hash, bool) {
	if tx == nil || tx.Type() != InvokeTxType {
		return common.Hash{}, false
	}
	opId, ok := tx.Agnt2OperationID()
	if !ok {
		return common.Hash{}, false
	}
	agent, err := Sender(signer, tx)
	if err != nil {
		return common.Hash{}, false
	}
	return agnt2DeriveInvokeOutputHash(opId.WorkflowId, agent, tx.Data(), []byte{}), true
}

// FoldTypedReexecRoot computes the per-op re-exec MMR root + leaf count over the
// block's INVOKE + RESPOND typed ops, in block order (matching FoldTypedOpRoot).
// INVOKE binds (taskId, agent, callData); RESPOND additionally binds the parent
// INVOKE's committed outputHash — resolved from RespondTx.InvokeRef within THIS
// block — so a re-pointed parent is slashable (the first non-vacuous fraud
// detection; INVOKE alone is vacuous). The committed outputHash is re-derived here,
// so it equals the canonical value for every honest op. COMPOSE is Stage 5.
//
// M6: a RESPOND whose InvokeRef resolves to a PRIOR block's INVOKE (a same-block
// map miss) is SKIPPED — NOT folded with parentOut=0, which would be a
// self-consistent-but-false commitment. Producer + validator skip identically (the
// decision is deterministic from block contents), so they agree; cross-block
// RESPOND coverage is a documented deferral.
func FoldTypedReexecRoot(txs []*Transaction, signer Signer, resolveParent ReexecParentResolver) (common.Hash, uint64) {
	var leaves [][32]byte
	opOutput := make(map[common.Hash]common.Hash) // in-block op tx-hash -> committed outputHash
	for _, tx := range txs {
		if tx == nil {
			continue // guard, matching FoldTypedOpRoot / FoldInteractionRoot
		}
		var stepType uint8
		switch tx.Type() {
		case InvokeTxType:
			stepType = agnt2StepTypeInvoke
		case RespondTxType:
			stepType = agnt2StepTypeRespond
		default:
			continue
		}
		opId, ok := tx.Agnt2OperationID()
		if !ok {
			continue
		}
		agent, err := Sender(signer, tx)
		if err != nil {
			// Unrecoverable signer -> cannot fold (would also fail admission). Skip.
			continue
		}
		taskId := opId.WorkflowId

		var stepPayload []byte
		var committed common.Hash
		if stepType == agnt2StepTypeInvoke {
			callData := tx.Data()     // InvokeTx.Payload
			responseBytes := []byte{} // INVOKE: request-only
			committed = agnt2DeriveInvokeOutputHash(taskId, agent, callData, responseBytes)
			stepPayload = agnt2InvokeEnvelope(callData, responseBytes)
		} else {
			deps := tx.Agnt2Dependencies() // [InvokeRef]
			if len(deps) == 0 {
				continue
			}
			parentOut, present := opOutput[deps[0]]
			if !present && resolveParent != nil {
				// Cross-block: resolve the parent INVOKE's committed output from a
				// STRICTLY-PRIOR block via the state ring. The resolver's strictly-prior
				// guard ensures a same-block parent is NEVER served here (only by the map
				// above), and returns the exact stored value (= the same-block map value).
				parentOut, present = resolveParent(deps[0])
			}
			if !present {
				// M6: same-block miss AND (nil resolver OR cross-block miss / evicted past
				// the window). Skip — do NOT fold parentOut=0 (self-consistent-but-false).
				continue
			}
			callData := []byte{}       // RESPOND: no callData in the typed-VM model
			responseBytes := tx.Data() // RespondTx.ResponsePayload
			committed = agnt2DeriveRespondOutputHash(taskId, agent, parentOut, callData, responseBytes)
			stepPayload = agnt2RespondEnvelope(callData, responseBytes, parentOut)
		}
		leaves = append(leaves, agnt2ReexecLeaf(tx.Hash(), stepType, taskId, agent, stepPayload, committed))
		// Only an INVOKE's output can be a RESPOND's parent (InvokeRef must point at
		// an INVOKE). Store ONLY INVOKE outputs so the fold self-enforces this — a
		// RESPOND whose InvokeRef points at another RESPOND finds no entry and is
		// treated as a cross-block/absent parent (M6 skip) rather than folding a
		// type-confused parent. Does not rely on validateAGNT2TypedOpOrder running.
		if stepType == agnt2StepTypeInvoke {
			opOutput[tx.Hash()] = committed
		}
	}
	return foldMMR(leaves), uint64(len(leaves))
}
