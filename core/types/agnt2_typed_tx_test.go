package types

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

type agnt2TypedTxFixture struct {
	TxType          string                 `json:"tx_type"`
	SigningKeyIndex int                    `json:"signing_key_index"`
	Fields          map[string]interface{} `json:"fields"`
}

func TestAgnt2TypedTxRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		tx   *Transaction
		typ  uint8
	}{
		{name: "InvokeTx", tx: NewTx(testInvokeTx()), typ: InvokeTxType},
		{name: "RespondTx", tx: NewTx(testRespondTx()), typ: RespondTxType},
		{name: "ComposeTypedTx", tx: NewTx(testComposeTypedTx()), typ: ComposeTypedTxType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := tt.tx.MarshalBinary()
			if err != nil {
				t.Fatalf("failed to encode: %v", err)
			}
			if encoded[0] != tt.typ {
				t.Fatalf("wrong type byte: got %#x, want %#x", encoded[0], tt.typ)
			}
			var decoded Transaction
			if err := decoded.UnmarshalBinary(encoded); err != nil {
				t.Fatalf("failed to decode: %v", err)
			}
			if decoded.Type() != tt.typ {
				t.Fatalf("wrong decoded type: got %#x, want %#x", decoded.Type(), tt.typ)
			}
			if decoded.Hash() != tt.tx.Hash() {
				t.Fatalf("hash mismatch: got %s, want %s", decoded.Hash(), tt.tx.Hash())
			}
		})
	}
}

func TestAgnt2SighashDeterminism(t *testing.T) {
	tx := NewTx(testInvokeTx())
	signer := NewLondonSigner(big.NewInt(9001))
	expected := signer.Hash(tx)

	for i := 0; i < 100; i++ {
		if hash := signer.Hash(tx); hash != expected {
			t.Fatalf("sighash changed on iteration %d: got %s, want %s", i, hash, expected)
		}
	}
}

func TestAgnt2IntrinsicGasSurcharge(t *testing.T) {
	tests := []struct {
		name string
		tx   *Transaction
		want uint64
	}{
		{name: "invoke", tx: NewTx(testInvokeTx()), want: Agnt2TypedTxPerStepGas + Agnt2ReexecRingWriteGas},
		{name: "respond", tx: NewTx(testRespondTx()), want: Agnt2TypedTxPerStepGas + Agnt2ReexecRingReadGas},
		{name: "compose", tx: NewTx(testComposeTypedTx()), want: 2 * Agnt2TypedTxPerStepGas},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tx.Agnt2IntrinsicGasSurcharge(); got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestAgnt2MalformedEnvelopes(t *testing.T) {
	t.Run("truncated RLP", func(t *testing.T) {
		var tx Transaction
		err := tx.UnmarshalBinary([]byte{InvokeTxType, 0xc1, 0x01})
		if err == nil {
			t.Fatal("expected error for truncated RLP")
		}
	})

	t.Run("wrong type byte", func(t *testing.T) {
		var tx Transaction
		err := tx.UnmarshalBinary([]byte{0x7d, 0xc0})
		if !errors.Is(err, ErrTxTypeNotSupported) {
			t.Fatalf("got %v, want %v", err, ErrTxTypeNotSupported)
		}
	})

	t.Run("AgentRole > 64 bytes", func(t *testing.T) {
		txdata := testInvokeTx()
		txdata.AgentRole = strings.Repeat("a", Agnt2MaxAgentRoleBytes+1)
		tx := NewTx(txdata)
		if _, err := tx.MarshalBinary(); !errors.Is(err, ErrAgnt2AgentRoleTooLong) {
			t.Fatalf("got %v, want %v", err, ErrAgnt2AgentRoleTooLong)
		}
	})

	t.Run("AgentRole non-NFC", func(t *testing.T) {
		txdata := testInvokeTx()
		txdata.AgentRole = "e\u0301"
		tx := NewTx(txdata)
		if _, err := tx.MarshalBinary(); !errors.Is(err, ErrAgnt2AgentRoleNFC) {
			t.Fatalf("got %v, want %v", err, ErrAgnt2AgentRoleNFC)
		}
	})

	t.Run("Payload > 16 KiB", func(t *testing.T) {
		txdata := testInvokeTx()
		txdata.Payload = make([]byte, Agnt2MaxPayloadBytes+1)
		tx := NewTx(txdata)
		if _, err := tx.MarshalBinary(); !errors.Is(err, ErrAgnt2PayloadTooLarge) {
			t.Fatalf("got %v, want %v", err, ErrAgnt2PayloadTooLarge)
		}
	})

	t.Run("DepInvokeIds nil", func(t *testing.T) {
		txdata := testInvokeTx()
		txdata.DepInvokeIds = nil
		tx := NewTx(txdata)
		if _, err := tx.MarshalBinary(); !errors.Is(err, ErrAgnt2DepInvokeIdsNil) {
			t.Fatalf("got %v, want %v", err, ErrAgnt2DepInvokeIdsNil)
		}
	})

	t.Run("empty DepInvokeIds encodes as empty RLP list", func(t *testing.T) {
		txdata := testInvokeTx()
		txdata.DepInvokeIds = []common.Hash{}
		tx := NewTx(txdata)
		encoded, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(encoded, []byte{0xc0}) {
			t.Fatalf("encoded transaction does not contain empty DepInvokeIds list: %x", encoded)
		}
	})
}

func TestAgnt2GoldenVectors(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "..", "golden", "typed-tx")
	for _, dir := range []string{"invoke", "respond", "compose-typed"} {
		dir := dir
		t.Run(dir, func(t *testing.T) {
			files, err := filepath.Glob(filepath.Join(goldenDir, dir, "*.input.json"))
			if err != nil {
				t.Fatal(err)
			}
			if len(files) == 0 {
				t.Fatalf("no golden input fixtures found in %s", filepath.Join(goldenDir, dir))
			}
			for _, inputPath := range files {
				inputPath := inputPath
				t.Run(filepath.Base(inputPath), func(t *testing.T) {
					basePath := strings.TrimSuffix(inputPath, ".input.json")
					expectedBytes := readHexFile(t, basePath+".expected.hex")
					expectedHash := common.BytesToHash(readHexFile(t, basePath+".expected.hash"))
					expectedSighash := common.BytesToHash(readHexFile(t, basePath+".expected.sighash"))

					var tx Transaction
					if err := tx.UnmarshalBinary(expectedBytes); err != nil {
						t.Fatalf("failed to decode golden tx: %v", err)
					}
					if tx.Hash() != expectedHash {
						t.Fatalf("hash mismatch: got %s, want %s", tx.Hash(), expectedHash)
					}
					roundTrip, err := tx.MarshalBinary()
					if err != nil {
						t.Fatalf("failed to re-encode golden tx: %v", err)
					}
					if !bytes.Equal(roundTrip, expectedBytes) {
						t.Fatalf("RLP mismatch:\n got  %x\n want %x", roundTrip, expectedBytes)
					}

					fixture := readFixture(t, inputPath)
					chainID := parseFixtureBig(t, fixture.Fields["chain_id"])
					signer := NewLondonSigner(chainID)
					if got := signer.Hash(&tx); got != expectedSighash {
						t.Fatalf("sighash mismatch: got %s, want %s", got, expectedSighash)
					}
					assertGoldenSender(t, signer, &tx, goldenDir, fixture.SigningKeyIndex)
				})
			}
		})
	}
}

func testInvokeTx() *InvokeTx {
	return &InvokeTx{
		ChainID:      big.NewInt(9001),
		Nonce:        1,
		GasTipCap:    big.NewInt(1_000_000_000),
		GasFeeCap:    big.NewInt(20_000_000_000),
		Gas:          100000,
		WorkflowId:   common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		StepId:       1,
		AgentRole:    "worker-a",
		DepInvokeIds: []common.Hash{common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")},
		Payload:      common.FromHex("0xdeadbeef"),
		V:            new(big.Int),
		R:            big.NewInt(1),
		S:            big.NewInt(1),
	}
}

func testRespondTx() *RespondTx {
	return &RespondTx{
		ChainID:         big.NewInt(9001),
		Nonce:           1,
		GasTipCap:       big.NewInt(1_000_000_000),
		GasFeeCap:       big.NewInt(20_000_000_000),
		Gas:             100000,
		WorkflowId:      common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		StepId:          1,
		InvokeRef:       common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333"),
		ResponsePayload: common.FromHex("0xcafebabe"),
		Status:          0,
		V:               new(big.Int),
		R:               big.NewInt(1),
		S:               big.NewInt(1),
	}
}

func testComposeTypedTx() *ComposeTypedTx {
	return &ComposeTypedTx{
		ChainID:    big.NewInt(9001),
		Nonce:      1,
		GasTipCap:  big.NewInt(1_000_000_000),
		GasFeeCap:  big.NewInt(20_000_000_000),
		Gas:        100000,
		WorkflowId: common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		StepCount:  2,
		StepWorkflowRoots: []common.Hash{
			common.HexToHash("0x4444444444444444444444444444444444444444444444444444444444444444"),
			common.HexToHash("0x5555555555555555555555555555555555555555555555555555555555555555"),
		},
		Payouts: []*big.Int{big.NewInt(1), big.NewInt(2)},
		V:       new(big.Int),
		R:       big.NewInt(1),
		S:       big.NewInt(1),
	}
}

func readFixture(t *testing.T, path string) agnt2TypedTxFixture {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture agnt2TypedTxFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func readHexFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out, err := hexutil.Decode(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func parseFixtureBig(t *testing.T, val interface{}) *big.Int {
	t.Helper()
	switch v := val.(type) {
	case float64:
		return big.NewInt(int64(v))
	case string:
		n, ok := new(big.Int).SetString(strings.TrimPrefix(v, "0x"), 10)
		if strings.HasPrefix(v, "0x") {
			n, ok = new(big.Int).SetString(strings.TrimPrefix(v, "0x"), 16)
		}
		if !ok {
			t.Fatalf("invalid integer fixture value %v", val)
		}
		return n
	default:
		t.Fatalf("invalid integer fixture value %T", val)
		return nil
	}
}

func assertGoldenSender(t *testing.T, signer Signer, tx *Transaction, goldenDir string, keyIndex int) {
	t.Helper()
	keyData, err := os.ReadFile(filepath.Join(goldenDir, "scripts", "test-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	if err := json.Unmarshal(keyData, &keys); err != nil {
		t.Fatal(err)
	}
	priv, err := crypto.HexToECDSA(strings.TrimPrefix(keys[keyIndex], "0x"))
	if err != nil {
		t.Fatal(err)
	}
	want := crypto.PubkeyToAddress(priv.PublicKey)
	got, err := Sender(signer, tx)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("sender mismatch: got %s, want %s", got, want)
	}
}

func TestAgnt2TypedTxDecodeRLPEnvelope(t *testing.T) {
	tx := NewTx(testInvokeTx())
	var envelope bytes.Buffer
	if err := tx.EncodeRLP(&envelope); err != nil {
		t.Fatal(err)
	}
	var decoded Transaction
	if err := decoded.DecodeRLP(rlp.NewStream(bytes.NewReader(envelope.Bytes()), 0)); err != nil {
		t.Fatal(err)
	}
	if decoded.Type() != InvokeTxType {
		t.Fatalf("decoded type %x, want %x", decoded.Type(), InvokeTxType)
	}
}
