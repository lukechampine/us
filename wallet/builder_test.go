package wallet

import (
	"testing"

	"gitlab.com/NebulousLabs/Sia/types"
)

func BenchmarkSumOutputs(b *testing.B) {
	outputs := make([]UnspentOutput, 1000)
	for i := range outputs {
		outputs[i].Value = types.SiacoinPrecision
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = SumOutputs(outputs)
	}
}
