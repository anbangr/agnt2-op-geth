package vm

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// noopPrecompile is the F5 control: a precompile that does the same calldata-
// length validation as a real one but performs no MMR work, no keccak per
// leaf, and no event emission. It establishes the lower bound on per-call
// cost so the AGNT2 overhead can be reported as a percentage delta.
type noopPrecompile struct{}

func (noopPrecompile) Run(input []byte) ([]byte, error) {
	if len(input) < 5 {
		return []byte{0x02}, ErrExecutionReverted
	}
	return nil, nil
}

func benchInputForSteps(b *testing.B, steps uint32) []byte {
	b.Helper()
	wfID := "f5-bench-workflow"
	expectedHash := crypto.Keccak256([]byte(wfID))
	leaves := makeChainedLeaves(expectedHash, int(steps))
	return makeInputWithLeaves(wfID, leaves)
}

// BenchmarkAgnt2Run measures the wall-clock cost of agnt2Interaction.Run()
// for a range of step counts. Reports ns/op + bytes/op via -benchmem.
//
// Run with:
//
//	go test -bench=BenchmarkAgnt2Run -benchmem -run=^$ ./core/vm/
//
// Step-count fan-out (1, 3, 5, 100) covers:
//   - 1 step:   single-peak MMR, smallest workflow
//   - 3 steps:  multi-peak MMR (peaks 2+1, one fold)
//   - 5 steps:  multi-peak MMR (peaks 4+1, one fold)
//   - 100 steps: realistic large workflow, exercises the per-step-gas regime
func BenchmarkAgnt2Run(b *testing.B) {
	cases := []struct {
		name  string
		steps uint32
	}{
		{"1step", 1},
		{"3step", 3},
		{"5step", 5},
		{"100step", 100},
	}
	for _, tc := range cases {
		tc := tc
		b.Run(tc.name, func(b *testing.B) {
			c := &agnt2Interaction{}
			input := benchInputForSteps(b, tc.steps)
			b.SetBytes(int64(len(input)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := c.Run(input); err != nil {
					b.Fatalf("Run failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkAgnt2Noop is the F5 control: a precompile that accepts the same
// calldata as agnt2Interaction.Run() but does no real work. The delta
// (BenchmarkAgnt2Run - BenchmarkAgnt2Noop) is the AGNT2 protocol overhead.
//
// Same step-count fan-out as BenchmarkAgnt2Run for direct comparison.
func BenchmarkAgnt2Noop(b *testing.B) {
	cases := []struct {
		name  string
		steps uint32
	}{
		{"1step", 1},
		{"3step", 3},
		{"5step", 5},
		{"100step", 100},
	}
	for _, tc := range cases {
		tc := tc
		b.Run(tc.name, func(b *testing.B) {
			c := noopPrecompile{}
			input := benchInputForSteps(b, tc.steps)
			b.SetBytes(int64(len(input)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := c.Run(input); err != nil {
					b.Fatalf("Run failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkAgnt2RequiredGas isolates the cost of RequiredGas (called by the
// EVM before dispatch). Should be O(1) per call after the Phase 5 fix
// (validateAndBuildMMR extraction); regressions here mean the keccak loop
// crept back into the gas-estimation path.
func BenchmarkAgnt2RequiredGas(b *testing.B) {
	c := &agnt2Interaction{}
	input := benchInputForSteps(b, 100)
	b.SetBytes(int64(len(input)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.RequiredGas(input)
	}
}
