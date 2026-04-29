package types

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// AGNT2InteractionPrecompileAddress mirrors the value defined in core/vm and
// params for the address that emits AGNT2 leaf-event logs. It is duplicated
// here (rather than imported) because core/types must not depend on core/vm
// (cyclic) and core/types is below params/agnt2_params.go in the dep graph
// at this exact site. The byte layout is locked by ADR 002 §Calldata Format
// and any drift fires TestFoldInteractionRoot_AddressLockedAt0x0BC2.
var agnt2InteractionPrecompileAddress = common.BytesToAddress([]byte{0x0B, 0xC2})

// agnt2LeafEventTopic0 is the topic[0] hash of the canonical AGNT2 leaf
// event signature. Re-derived here to avoid importing core/vm; the value is
// pinned by TestFoldInteractionRoot_Topic0Locked against the same string
// used by core/vm/agnt2_emit.go.
var agnt2LeafEventTopic0 = func() common.Hash {
	const sig = "AGNT2LeafEvent(bytes32,uint32,bytes32,bytes32,bytes32,bytes32)"
	var h common.Hash
	copy(h[:], crypto.Keccak256([]byte(sig)))
	return h
}()

// emptyMMRRoot is the keccak256 of the empty byte string — what the MMR
// reports for zero leaves. Matches the off-chain reference in trace.ts and
// the in-EVM agnt2MMR.getRoot zero-leaf branch.
var emptyMMRRoot = func() common.Hash {
	var h common.Hash
	copy(h[:], crypto.Keccak256([]byte{}))
	return h
}()

// FoldInteractionRoot recomputes the AGNT2 interaction MMR root and leaf
// count from the receipts of a single block. It iterates receipts in the
// canonical (txIndex, logIndex) order — receipts are already in transaction
// order, and Receipt.Logs preserves emission order within the transaction.
//
// This is the consensus-deterministic fold that block import uses to verify
// (header.InteractionRoot, header.InteractionCount) match the receipt-derived
// values. The sequencer must populate the header from the same fold.
//
// Filtering rule (locked):
//   - log.Address == 0x0BC2 (AGNT2 precompile address)
//   - len(log.Topics) >= 1 AND log.Topics[0] == keccak256(agnt2LeafEventSig)
//   - len(log.Data) == 160 (5 × 32-byte words per ADR 002 §Leaf Layout)
//
// Per-leaf hash extracted from Data[128:160] — the LeafHash slot already
// pre-computed by the precompile during the per-step loop. Re-deriving from
// (workflowIDHash, stepID, agentRole, payout, prevLeafHash) here would
// duplicate the precompile's keccak work for no security gain — the receipt
// trie commits to log bytes via Hash(receipt) → header.ReceiptHash, so a
// tampered Data slot would fail receipt-trie validation BEFORE we got here.
func FoldInteractionRoot(receipts []*Receipt) (common.Hash, uint64) {
	var leaves [][32]byte
	for _, r := range receipts {
		if r == nil {
			continue
		}
		for _, lg := range r.Logs {
			if lg == nil {
				continue
			}
			if lg.Address != agnt2InteractionPrecompileAddress {
				continue
			}
			if len(lg.Topics) < 1 || lg.Topics[0] != agnt2LeafEventTopic0 {
				continue
			}
			if len(lg.Data) != 160 {
				continue
			}
			var leaf [32]byte
			copy(leaf[:], lg.Data[128:160])
			leaves = append(leaves, leaf)
		}
	}
	return foldMMR(leaves), uint64(len(leaves))
}

// foldMMR mirrors core/vm/agnt2_mmr.go's bit-decomposition + right-to-left
// peak combine. Duplicated here (rather than imported from core/vm) to
// preserve the package boundary; both are byte-for-byte tested against the
// locked TS reference vectors (encoding_vectors_test.go in the op-node side
// + the precompile tests in core/vm).
//
// Empty input returns keccak256("") to match the empty-MMR convention.
func foldMMR(leaves [][32]byte) common.Hash {
	n := uint64(len(leaves))
	if n == 0 {
		return emptyMMRRoot
	}
	var peaks [][32]byte
	var offset uint64 = 0
	for bit := 31; bit >= 0; bit-- {
		size := uint64(1) << uint(bit)
		if n&size != 0 {
			peaks = append(peaks, buildPerfectTree(leaves[offset:offset+size]))
			offset += size
		}
	}
	root := peaks[len(peaks)-1]
	for i := len(peaks) - 2; i >= 0; i-- {
		var combined [64]byte
		copy(combined[0:32], peaks[i][:])
		copy(combined[32:64], root[:])
		copy(root[:], crypto.Keccak256(combined[:]))
	}
	var out common.Hash
	copy(out[:], root[:])
	return out
}

func buildPerfectTree(nodes [][32]byte) [32]byte {
	if len(nodes) == 1 {
		return nodes[0]
	}
	next := make([][32]byte, 0, len(nodes)/2)
	for i := 0; i < len(nodes); i += 2 {
		var combined [64]byte
		copy(combined[0:32], nodes[i][:])
		copy(combined[32:64], nodes[i+1][:])
		var hash [32]byte
		copy(hash[:], crypto.Keccak256(combined[:]))
		next = append(next, hash)
	}
	return buildPerfectTree(next)
}

// FoldTypedOpRoot computes the AGNT2 typed-op MMR root and leaf count from
// the typed transactions (InvokeTx/RespondTx/ComposeTypedTx) in a block. The
// MMR leaves are the canonical tx hashes in block order. Blocks with no typed
// transactions return (emptyMMRRoot, 0).
func FoldTypedOpRoot(txs []*Transaction) (common.Hash, uint64) {
	var leaves [][32]byte
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		switch tx.Type() {
		case InvokeTxType, RespondTxType, ComposeTypedTxType:
			h := tx.Hash()
			var leaf [32]byte
			copy(leaf[:], h[:])
			leaves = append(leaves, leaf)
		}
	}
	return foldMMR(leaves), uint64(len(leaves))
}

// AGNT2InteractionPrecompileAddressForTest exposes the package-private
// address constant for tests in other packages that need to construct
// synthetic AGNT2 logs (e.g., block-import validation tests). Production
// code never calls this — sequencer + verifier both bind to the agreed
// address through their own modules.
func AGNT2InteractionPrecompileAddressForTest() common.Address {
	return agnt2InteractionPrecompileAddress
}

// AGNT2LeafEventTopic0ForTest exposes the topic[0] constant for tests.
func AGNT2LeafEventTopic0ForTest() common.Hash {
	return agnt2LeafEventTopic0
}

// EncodeAGNT2LeafLogData packs (stepIndex, stepIDHash, agentRoleHash,
// payout, leafHash) into the 160-byte data layout used by the precompile's
// log emission. Test-only helper.
func EncodeAGNT2LeafLogData(stepIndex uint32, stepIDHash, agentRoleHash, payout, leafHash [32]byte) []byte {
	out := make([]byte, 0, 160)
	var stepWord [32]byte
	binary.BigEndian.PutUint32(stepWord[28:32], stepIndex)
	out = append(out, stepWord[:]...)
	out = append(out, stepIDHash[:]...)
	out = append(out, agentRoleHash[:]...)
	out = append(out, payout[:]...)
	out = append(out, leafHash[:]...)
	return out
}
