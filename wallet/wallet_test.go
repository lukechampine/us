package wallet

import (
	"testing"

	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/frand"
)

func TestStandardAddress(t *testing.T) {
	for i := 0; i < 100; i++ {
		pk := types.SiaPublicKey{
			Algorithm: frand.Entropy128(),
			Key:       frand.Bytes(32),
		}
		if StandardAddress(pk) != StandardUnlockConditions(pk).UnlockHash() {
			t.Error("mismatch:", pk)
		}
	}
}

func BenchmarkNewSeed(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = NewSeed()
	}
}

func BenchmarkStandardAddress(b *testing.B) {
	b.ReportAllocs()
	pk := NewSeed().PublicKey(0)
	for i := 0; i < b.N; i++ {
		_ = StandardAddress(pk)
	}
}
