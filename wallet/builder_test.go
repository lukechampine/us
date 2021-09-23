package wallet

import (
	"testing"

	"go.sia.tech/siad/types"
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

func TestDistributeFunds(t *testing.T) {
	outputs := make([]UnspentOutput, 10)
	for i := range outputs {
		outputs[i].Value = types.SiacoinPrecision.Mul64(uint64(i + 1))
	}

	ins, fee, change := DistributeFunds(outputs, 5, types.SiacoinPrecision.Mul64(3), types.NewCurrency64(1e6))
	tot := types.SiacoinPrecision.Mul64(3).Mul64(5).Add(fee).Add(change)
	if !SumOutputs(ins).Equals(tot) {
		t.Error(len(ins), fee, change)
	}

	// should use the most valuable output, worth 10 SC
	ins, fee, change = DistributeFunds(outputs, 3, types.SiacoinPrecision.Mul64(3), types.ZeroCurrency)
	if len(ins) != 1 || !fee.IsZero() || !change.Equals(types.SiacoinPrecision) {
		t.Error(len(ins), fee, change)
	}

	ins, fee, change = DistributeFunds(outputs, 30, types.SiacoinPrecision.Div64(2), types.ZeroCurrency)
	if len(ins) != 2 || !fee.IsZero() || !change.Equals(types.SiacoinPrecision.Mul64(4)) {
		t.Error(len(ins), fee, change)
	}

	// should use outputs worth 9+8+7=24 SC, ignoring output already worth 10 SC
	ins, fee, change = DistributeFunds(outputs, 2, types.SiacoinPrecision.Mul64(10), types.ZeroCurrency)
	if len(ins) != 3 || !fee.IsZero() || !change.Equals(types.SiacoinPrecision.Mul64(4)) {
		t.Error(len(ins), fee, change)
	}

	// insufficient funds
	ins, fee, change = DistributeFunds(outputs, 1, types.SiacoinPrecision.Mul64(100), types.ZeroCurrency)
	if len(ins) != 0 {
		t.Error(len(ins), fee, change)
	}

	// all outputs already worth 1 SC
	ins, fee, change = DistributeFunds(outputs[:1], 1, types.SiacoinPrecision.Mul64(100), types.ZeroCurrency)
	if len(ins) != 0 {
		t.Error(len(ins), fee, change)
	}

}
