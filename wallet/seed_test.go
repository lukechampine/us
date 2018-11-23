package wallet

import (
	"strings"
	"testing"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/types"
)

func TestSeedPhrase(t *testing.T) {
	for i := 0; i < 1000; i++ {
		s := NewSeed()
		s2, err := SeedFromPhrase(s.String())
		if err != nil {
			t.Fatal(err)
		} else if s2 != s {
			t.Fatal("seed loaded from phrase does not match")
		}
	}
	phrase := strings.Fields(NewSeed().String())
	phrase[len(phrase)-1] = phrase[0]
	if _, err := SeedFromPhrase(strings.Join(phrase, " ")); err == nil {
		t.Fatal("expected invalid checksum error")
	}
}

func TestSeedPublicKey(t *testing.T) {
	for i := 0; i < 10; i++ {
		s := NewSeed()
		for j := 0; j < 10; j++ {
			pk := s.PublicKey(uint64(j))
			_, spk := crypto.GenerateKeyPairDeterministic(crypto.HashAll(s.siadSeed, j))
			pk2 := types.Ed25519PublicKey(spk)
			if pk.String() != pk2.String() {
				t.Fatal("key mismatch")
			}
		}
	}
}

func BenchmarkSeedPublicKey(b *testing.B) {
	b.ReportAllocs()
	s := NewSeed()
	for i := 0; i < b.N; i++ {
		_ = s.PublicKey(0)
	}
}

func BenchmarkSeedPhrase(b *testing.B) {
	b.ReportAllocs()
	s := NewSeed()
	for i := 0; i < b.N; i++ {
		_ = s.String()
	}
}

func BenchmarkParallelGen(b *testing.B) {
	b.ReportAllocs()
	_ = NewSeedManager(NewSeed(), uint64(b.N))
}
