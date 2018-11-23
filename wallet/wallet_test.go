package wallet

import (
	"testing"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/types"
	"gitlab.com/NebulousLabs/fastrand"
)

func TestStandardAddress(t *testing.T) {
	pk := types.SiaPublicKey{
		Key: make([]byte, 32),
	}
	for i := 0; i < 100; i++ {
		fastrand.Read(pk.Algorithm[:])
		fastrand.Read(pk.Key)
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

func BenchmarkSignHash(b *testing.B) {
	b.ReportAllocs()
	sk := NewSeed().SecretKey(0)
	for i := 0; i < b.N; i++ {
		_ = sk.SignHash(crypto.Hash{})
	}
}
