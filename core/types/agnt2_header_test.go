package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// TestFoldInteractionRoot_AddressLockedAt0x0BC2 pins the precompile address
// against ADR 002 byte layout. If it ever drifts, both the sequencer-side
// and verifier-side fold would silently include logs from a different
// contract — a consensus bug.
func TestFoldInteractionRoot_AddressLockedAt0x0BC2(t *testing.T) {
	want := [20]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0B, 0xC2}
	if [20]byte(agnt2InteractionPrecompileAddress) != want {
		t.Fatalf("ADR 002 lock broken: %x", agnt2InteractionPrecompileAddress)
	}
}

// TestFoldInteractionRoot_Topic0Locked pins the leaf-event topic[0] hash
// against the canonical signature string. The string and topic[0] must
// match the values used by core/vm/agnt2_emit.go so that the fold sees
// the logs the precompile actually emits.
func TestFoldInteractionRoot_Topic0Locked(t *testing.T) {
	const sig = "AGNT2LeafEvent(bytes32,uint32,bytes32,bytes32,bytes32,bytes32)"
	want := crypto.Keccak256([]byte(sig))
	if !bytes.Equal(agnt2LeafEventTopic0[:], want) {
		t.Fatalf("topic[0] drifted: have %x want %x", agnt2LeafEventTopic0, want)
	}
}

// TestFoldInteractionRoot_Empty: zero leaves → keccak256("") root, count 0.
func TestFoldInteractionRoot_Empty(t *testing.T) {
	root, count := FoldInteractionRoot(nil)
	if count != 0 {
		t.Fatalf("expected count 0, got %d", count)
	}
	want := crypto.Keccak256([]byte{})
	if !bytes.Equal(root[:], want) {
		t.Fatalf("empty fold root mismatch: have %x want %x", root, want)
	}
}

// TestFoldInteractionRoot_v1_3step uses the locked TS reference vector.
// Three leaves chained as the canonical encoding tests build them, emitted
// as logs from the AGNT2 precompile address. The fold must reproduce the
// reference root.
func TestFoldInteractionRoot_v1_3step(t *testing.T) {
	leaf0 := encodeLeafForTest("test-wf-001", "step-1", "worker-a", big.NewInt(1000), [32]byte{})
	leaf1 := encodeLeafForTest("test-wf-001", "step-2", "worker-b", big.NewInt(2000), leaf0)
	leaf2 := encodeLeafForTest("test-wf-001", "step-3", "worker-c", big.NewInt(3000), leaf1)

	receipts := []*Receipt{
		{Logs: []*Log{makeAgnt2Log(0, leaf0), makeAgnt2Log(1, leaf1), makeAgnt2Log(2, leaf2)}},
	}
	root, count := FoldInteractionRoot(receipts)

	if count != 3 {
		t.Fatalf("expected count 3, got %d", count)
	}
	want := common.HexToHash("0xd54c19717603e20fbf82ff44e90eafd7d1ad14ef4d7811f8802cc3c078cc86c3")
	if root != want {
		t.Fatalf("root mismatch: have %x want %x", root, want)
	}
}

// TestFoldInteractionRoot_OrderingPreserved: the canonical fold order is
// (txIndex, logIndex). Receipts arrive in tx-index order from the
// processor; logs are appended in emission order within a transaction.
// This test verifies ordering matters: if we silently sorted, swapped, or
// dropped any log, the root would differ.
func TestFoldInteractionRoot_OrderingPreserved(t *testing.T) {
	leaf0 := encodeLeafForTest("wf-A", "step-1", "role-1", big.NewInt(100), [32]byte{})
	leaf1 := encodeLeafForTest("wf-B", "step-1", "role-2", big.NewInt(200), leaf0)
	leaf2 := encodeLeafForTest("wf-C", "step-1", "role-3", big.NewInt(300), leaf1)

	// Two distinct receipts: receipt 0 has leaf0+leaf1, receipt 1 has leaf2
	rOrdered := []*Receipt{
		{Logs: []*Log{makeAgnt2Log(0, leaf0), makeAgnt2Log(1, leaf1)}},
		{Logs: []*Log{makeAgnt2Log(2, leaf2)}},
	}
	// Reordered: receipt 1 first
	rSwapped := []*Receipt{
		{Logs: []*Log{makeAgnt2Log(2, leaf2)}},
		{Logs: []*Log{makeAgnt2Log(0, leaf0), makeAgnt2Log(1, leaf1)}},
	}

	rootOrdered, cOrdered := FoldInteractionRoot(rOrdered)
	rootSwapped, cSwapped := FoldInteractionRoot(rSwapped)

	if cOrdered != cSwapped {
		t.Fatalf("count drift across orderings — should be 3 each")
	}
	if rootOrdered == rootSwapped {
		t.Fatalf("ordering mattered yet roots match — fold is silently sorting (consensus bug)")
	}
}

// TestFoldInteractionRoot_IgnoresNonAGNT2Logs: logs from other contracts
// or with the wrong topic[0] must be skipped — only AGNT2 leaf logs
// participate in the fold.
func TestFoldInteractionRoot_IgnoresNonAGNT2Logs(t *testing.T) {
	leaf0 := encodeLeafForTest("wf-x", "step-1", "role-1", big.NewInt(1), [32]byte{})

	// Noise logs: wrong address, wrong topic, wrong data length
	noiseAddr := &Log{Address: common.BytesToAddress([]byte{0x01}), Topics: []common.Hash{agnt2LeafEventTopic0}, Data: make([]byte, 160)}
	noiseTopic := &Log{Address: agnt2InteractionPrecompileAddress, Topics: []common.Hash{common.HexToHash("0xdead")}, Data: make([]byte, 160)}
	noiseDataLen := &Log{Address: agnt2InteractionPrecompileAddress, Topics: []common.Hash{agnt2LeafEventTopic0}, Data: make([]byte, 32)}
	good := makeAgnt2Log(0, leaf0)

	receipts := []*Receipt{{Logs: []*Log{noiseAddr, noiseTopic, good, noiseDataLen}}}
	root, count := FoldInteractionRoot(receipts)
	if count != 1 {
		t.Fatalf("expected to keep exactly 1 AGNT2 log, got %d", count)
	}

	// Reproduce: only the good leaf folded
	wantRoot, _ := FoldInteractionRoot([]*Receipt{{Logs: []*Log{good}}})
	if root != wantRoot {
		t.Fatalf("noise logs leaked into fold: have %x want %x", root, wantRoot)
	}
}

// TestHeader_RLP_RoundtripWithInteractionFields: a header with the new
// optional fields populated must round-trip cleanly through RLP. The other
// optionals between BaseFee and InteractionRoot must also be set, because
// the chained-optional encoding (gen_header_rlp.go) writes 0x80 placeholders
// for any nil intermediate optional and the reflective decoder rejects
// 0x80 for *common.Hash. Production headers that set InteractionRoot are
// post-Isthmus, so they always carry the intermediate Optimism-stack
// fields too — this test mirrors that.
func TestHeader_RLP_RoundtripWithInteractionFields(t *testing.T) {
	root := common.HexToHash("0xd54c19717603e20fbf82ff44e90eafd7d1ad14ef4d7811f8802cc3c078cc86c3")
	count := uint64(7)
	beaconRoot := common.HexToHash("0xbeac")
	requestsHash := common.HexToHash("0xfeedbeef")
	blobGas := uint64(0)
	excessBlobGas := uint64(0)
	slot := uint64(42)

	h := &Header{
		ParentHash:       common.HexToHash("0x01"),
		UncleHash:        EmptyUncleHash,
		Root:             common.HexToHash("0x02"),
		TxHash:           EmptyTxsHash,
		ReceiptHash:      EmptyReceiptsHash,
		Difficulty:       big.NewInt(0),
		Number:           big.NewInt(100),
		GasLimit:         30_000_000,
		GasUsed:          21_000,
		Time:             1_700_000_000,
		Extra:            []byte("agnt2"),
		BaseFee:          big.NewInt(1_000_000_000),
		WithdrawalsHash:  &EmptyWithdrawalsHash,
		BlobGasUsed:      &blobGas,
		ExcessBlobGas:    &excessBlobGas,
		ParentBeaconRoot: &beaconRoot,
		RequestsHash:     &requestsHash,
		SlotNumber:       &slot,
		InteractionRoot:  &root,
		InteractionCount: &count,
	}

	enc, err := rlp.EncodeToBytes(h)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	dec := new(Header)
	if err := rlp.DecodeBytes(enc, dec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if dec.InteractionRoot == nil || *dec.InteractionRoot != root {
		t.Fatalf("InteractionRoot lost on roundtrip: %v", dec.InteractionRoot)
	}
	if dec.InteractionCount == nil || *dec.InteractionCount != count {
		t.Fatalf("InteractionCount lost on roundtrip: %v", dec.InteractionCount)
	}
}

// TestHeader_RLP_BackwardsCompatible_OldHeaderDecodesCleanly: a header
// encoded WITHOUT the new fields must still decode under the new struct,
// with the new fields == nil. This is the load-bearing fork-gate
// invariant — pre-Isthmus headers never carried these fields and AGNT2
// nodes must still read them as the original chain did.
func TestHeader_RLP_BackwardsCompatible_OldHeaderDecodesCleanly(t *testing.T) {
	// Build an "old" header — no InteractionRoot/Count, no SlotNumber, etc.
	old := &Header{
		ParentHash:  common.HexToHash("0x01"),
		UncleHash:   EmptyUncleHash,
		Root:        common.HexToHash("0x02"),
		TxHash:      EmptyTxsHash,
		ReceiptHash: EmptyReceiptsHash,
		Difficulty:  big.NewInt(0),
		Number:      big.NewInt(50),
		GasLimit:    30_000_000,
		GasUsed:     21_000,
		Time:        1_690_000_000,
		BaseFee:     big.NewInt(7),
	}
	enc, err := rlp.EncodeToBytes(old)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	dec := new(Header)
	if err := rlp.DecodeBytes(enc, dec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.InteractionRoot != nil {
		t.Fatalf("expected nil InteractionRoot for legacy header, got %x", dec.InteractionRoot)
	}
	if dec.InteractionCount != nil {
		t.Fatalf("expected nil InteractionCount for legacy header, got %d", *dec.InteractionCount)
	}
	if dec.SlotNumber != nil {
		t.Fatalf("expected nil SlotNumber for legacy header, got %d", *dec.SlotNumber)
	}
}

// TestHeader_HashChangesWithInteractionFields: setting InteractionRoot
// MUST change Hash(); otherwise the fields aren't actually committed.
func TestHeader_HashChangesWithInteractionFields(t *testing.T) {
	root := common.HexToHash("0x" + fmt.Sprintf("%064x", 1234))
	count := uint64(2)

	hNoFields := &Header{
		ParentHash:  common.HexToHash("0x01"),
		UncleHash:   EmptyUncleHash,
		Root:        common.HexToHash("0x02"),
		TxHash:      EmptyTxsHash,
		ReceiptHash: EmptyReceiptsHash,
		Difficulty:  big.NewInt(0),
		Number:      big.NewInt(1),
		GasLimit:    1,
		Time:        1,
	}
	hWithFields := *hNoFields
	hWithFields.InteractionRoot = &root
	hWithFields.InteractionCount = &count

	if hNoFields.Hash() == hWithFields.Hash() {
		t.Fatalf("hash unchanged after setting interaction fields — RLP encode is dropping them")
	}
}

// makeAgnt2Log builds a log structurally identical to one the precompile
// would emit for the given (stepIndex, leafHash). Topics[1] (workflowIDHash)
// is filled with stepIndex||0 padding for test determinism — the fold only
// inspects Topics[0] and Data[128:160].
func makeAgnt2Log(stepIndex uint32, leafHash [32]byte) *Log {
	var stepWord [32]byte
	binary.BigEndian.PutUint32(stepWord[28:32], stepIndex)

	// Synthesize plausible (workflowIDHash, stepIDHash, agentRoleHash, payout) —
	// only leafHash is read by the fold.
	var wfHash, stepIDHash, agentRoleHash, payout [32]byte
	wfHash[0] = 0xaa
	stepIDHash[0] = 0xbb
	agentRoleHash[0] = 0xcc
	payout[31] = 0x01

	data := EncodeAGNT2LeafLogData(stepIndex, stepIDHash, agentRoleHash, payout, leafHash)

	return &Log{
		Address: agnt2InteractionPrecompileAddress,
		Topics:  []common.Hash{agnt2LeafEventTopic0, common.BytesToHash(wfHash[:])},
		Data:    data,
	}
}

// encodeLeafForTest mirrors the canonical 160-byte tight packing leaf hash
// used by the off-chain TS reference and by op-geth's agnt2MMR.
func encodeLeafForTest(workflowID, stepID, agentRole string, payout *big.Int, prevLeafHash [32]byte) [32]byte {
	var buf []byte
	buf = append(buf, crypto.Keccak256([]byte(workflowID))...)
	buf = append(buf, crypto.Keccak256([]byte(stepID))...)
	buf = append(buf, crypto.Keccak256([]byte(agentRole))...)
	padded := make([]byte, 32)
	payout.FillBytes(padded)
	buf = append(buf, padded...)
	buf = append(buf, prevLeafHash[:]...)

	var h [32]byte
	copy(h[:], crypto.Keccak256(buf))
	return h
}
