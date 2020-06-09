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

func TestDistributeFunds(t *testing.T) {
	outputs := make([]UnspentOutput, 10)
	for i := range outputs {
		outputs[i].Value = types.SiacoinPrecision
	}

	n, fee, change := DistributeFunds(outputs, types.SiacoinPrecision, types.ZeroCurrency)
	if n != 10 || !fee.IsZero() || !change.IsZero() {
		t.Fatal(n, fee, change)
	}

	n, fee, change = DistributeFunds(outputs, types.SiacoinPrecision.Div64(2), types.ZeroCurrency)
	if n != 20 || !fee.IsZero() || !change.IsZero() {
		t.Fatal(n, fee, change)
	}

	n, fee, change = DistributeFunds(outputs, types.SiacoinPrecision.Mul64(3), types.ZeroCurrency)
	if n != 3 || !fee.IsZero() || !change.Equals(types.SiacoinPrecision) {
		t.Fatal(n, fee, change)
	}

	n, fee, change = DistributeFunds(outputs, types.SiacoinPrecision.Mul64(3), types.NewCurrency64(1e6))
	tot := types.SiacoinPrecision.Mul64(3).Mul64(n).Add(fee).Add(change)
	if n != 3 || !SumOutputs(outputs).Equals(tot) {
		t.Fatal(n, fee, change)
	}

	n, fee, change = DistributeFunds(outputs, types.SiacoinPrecision.Mul64(100), types.ZeroCurrency)
	if n != 0 {
		t.Fatal(n)
	}
}
