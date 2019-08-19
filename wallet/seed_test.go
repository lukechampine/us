package wallet

import (
	"strings"
	"testing"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/frand"
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
	// generate random phrases; about 1 in 16 should have a valid checksum
	phrase := make([]string, 12)
	valid := 0
	for i := 0; i < 1000; i++ {
		for j := range phrase {
			phrase[j] = bip39EnglishWordList[frand.Intn(len(bip39EnglishWordList))]
		}
		if _, err := SeedFromPhrase(strings.Join(phrase, " ")); err == nil {
			valid++
		}
	}
	if valid < (1000/16)-20 || (1000/16)+20 < valid {
		t.Error("expected number of randomly-valid phrases to fall in [42,82); got", valid)
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
