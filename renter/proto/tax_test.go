package proto

import (
	"testing"

	"gitlab.com/NebulousLabs/Sia/types"
	"gitlab.com/NebulousLabs/fastrand"
)

func TestTaxAdjustedPayout(t *testing.T) {
	tests := []struct {
		in, out types.Currency
	}{
		{in: types.NewCurrency64(0), out: types.ZeroCurrency},
		{in: types.NewCurrency64(1), out: types.NewCurrency64(1)},
		{in: types.NewCurrency64(246411), out: types.NewCurrency64(256411)},
		{in: types.NewCurrency64(87654321), out: types.NewCurrency64(91204321)},
		{in: types.SiacoinPrecision, out: types.NewCurrency64(12125214156169).Mul64(85819740000)},
		{in: types.PostTax(types.TaxHardforkHeight+1, types.SiacoinPrecision), out: types.SiacoinPrecision},
	}
	for _, tt := range tests {
		if p := taxAdjustedPayout(tt.in); !p.Equals(tt.out) {
			t.Errorf("expected taxAdjustedPayout(%v) = %v, got %v", tt.in, tt.out, p)
		}
	}
}

func BenchmarkTaxAdjustedPayout(b *testing.B) {
	b.ReportAllocs()
	target := types.NewCurrency(fastrand.BigIntn(types.SiacoinPrecision.Big()))
	for i := 0; i < b.N; i++ {
		taxAdjustedPayout(target)
	}
}
