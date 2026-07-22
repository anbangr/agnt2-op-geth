// Copyright 2025 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package engine

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
)

// TestExecutableDataRoundTrip_AGNT2Roots is the regression guard for the engine-API
// blockhash-mismatch bug: the AGNT2 header roots (InteractionRoot/Count, TypedOpRoot/
// Count, and the B2' TypedReexecRoot/Count) are hashed header fields (rlp:"optional"),
// so a block carrying them must survive Block -> ExecutableData -> Block with an
// IDENTICAL block hash. TypedReexecRoot/Count were added to the header but not plumbed
// through ExecutableData, so ExecutableDataToBlock rebuilt the header without them and
// NewPayload rejected every typed-op block ("blockhash mismatch, want .. got .."),
// stalling the chain. This locks all three root/count pairs through the engine round
// trip (in-process struct AND JSON wire path).
func TestExecutableDataRoundTrip_AGNT2Roots(t *testing.T) {
	iRoot := common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	tRoot := common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
	rRoot := common.HexToHash("0xb2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2")
	ic, tc, rc := uint64(2), uint64(1), uint64(3)
	beaconRoot := common.HexToHash("0xbeac0000000000000000000000000000000000000000000000000000000000")
	zero := uint64(0)

	header := &types.Header{
		Difficulty:       common.Big0,
		Number:           big.NewInt(15),
		GasLimit:         30_000_000,
		GasUsed:          117_033,
		Time:             1_700_000_000,
		BaseFee:          big.NewInt(1_000_000_000),
		Root:             common.HexToHash("0xaa"),
		Extra:            []byte{},
		BlobGasUsed:      &zero,
		ExcessBlobGas:    &zero,
		ParentBeaconRoot: &beaconRoot,
		InteractionRoot:  &iRoot, InteractionCount: &ic,
		TypedOpRoot: &tRoot, TypedOpCount: &tc,
		TypedReexecRoot: &rRoot, TypedReexecCount: &rc,
	}
	block := types.NewBlock(header, &types.Body{Withdrawals: []*types.Withdrawal{}}, nil, nil, types.DefaultBlockConfig)
	want := block.Hash()

	env := BlockToExecutableData(block, common.Big0, nil, nil)
	pl := env.ExecutionPayload
	if pl.TypedReexecRoot == nil || *pl.TypedReexecRoot != rRoot {
		t.Fatalf("BlockToExecutableData dropped TypedReexecRoot: %v", pl.TypedReexecRoot)
	}
	if pl.TypedReexecCount == nil || *pl.TypedReexecCount != rc {
		t.Fatalf("BlockToExecutableData dropped TypedReexecCount: %v", pl.TypedReexecCount)
	}

	back, err := ExecutableDataToBlock(*pl, nil, &beaconRoot, nil, types.DefaultBlockConfig)
	if err != nil {
		t.Fatalf("ExecutableDataToBlock: %v", err)
	}
	if got := back.Hash(); got != want {
		t.Fatalf("round-trip block hash mismatch (the NewPayload blockhash-mismatch bug):\n got %s\nwant %s", got, want)
	}
	if h := back.Header(); h.TypedReexecRoot == nil || *h.TypedReexecRoot != rRoot ||
		h.TypedReexecCount == nil || *h.TypedReexecCount != rc {
		t.Fatalf("ExecutableDataToBlock did not restore the reexec fields")
	}

	// JSON wire path (op-node <-> op-geth): the fields must survive Marshal/Unmarshal.
	j, err := pl.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var pl2 ExecutableData
	if err := pl2.UnmarshalJSON(j); err != nil {
		t.Fatal(err)
	}
	if pl2.TypedReexecRoot == nil || *pl2.TypedReexecRoot != rRoot || pl2.TypedReexecCount == nil || *pl2.TypedReexecCount != rc {
		t.Fatalf("JSON round-trip dropped the reexec fields: root=%v count=%v", pl2.TypedReexecRoot, pl2.TypedReexecCount)
	}
}

func TestBlobs(t *testing.T) {
	var (
		emptyBlob          = new(kzg4844.Blob)
		emptyBlobCommit, _ = kzg4844.BlobToCommitment(emptyBlob)
		emptyBlobProof, _  = kzg4844.ComputeBlobProof(emptyBlob, emptyBlobCommit)
		emptyCellProof, _  = kzg4844.ComputeCellProofs(emptyBlob)
	)
	header := types.Header{}
	block := types.NewBlock(&header, &types.Body{Withdrawals: []*types.Withdrawal{}}, nil, nil, types.DefaultBlockConfig)

	sidecarWithoutCellProofs := types.NewBlobTxSidecar(types.BlobSidecarVersion0, []kzg4844.Blob{*emptyBlob}, []kzg4844.Commitment{emptyBlobCommit}, []kzg4844.Proof{emptyBlobProof})
	env := BlockToExecutableData(block, common.Big0, []*types.BlobTxSidecar{sidecarWithoutCellProofs}, nil)
	if len(env.BlobsBundle.Proofs) != 1 {
		t.Fatalf("Expect 1 proof in blobs bundle, got %v", len(env.BlobsBundle.Proofs))
	}

	sidecarWithCellProofs := types.NewBlobTxSidecar(types.BlobSidecarVersion0, []kzg4844.Blob{*emptyBlob}, []kzg4844.Commitment{emptyBlobCommit}, emptyCellProof)
	env = BlockToExecutableData(block, common.Big0, []*types.BlobTxSidecar{sidecarWithCellProofs}, nil)
	if len(env.BlobsBundle.Proofs) != 128 {
		t.Fatalf("Expect 128 proofs in blobs bundle, got %v", len(env.BlobsBundle.Proofs))
	}
}
