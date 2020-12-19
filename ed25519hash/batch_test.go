package ed25519hash

import (
	"crypto/ed25519"
	"fmt"
	"testing"

	"lukechampine.com/frand"
)

func TestVerifyBatch(t *testing.T) {
	keys := make([]ed25519.PublicKey, 10)
	hashes := make([][32]byte, len(keys))
	sigs := make([][]byte, len(keys))
	for i := range keys {
		pub, priv, _ := ed25519.GenerateKey(nil)
		keys[i] = pub
		hashes[i] = frand.Entropy256()
		sigs[i] = Sign(priv, hashes[i])
		if !Verify(pub, hashes[i], sigs[i]) {
			t.Fatal("individual sig failed verification")
		}
	}
	if !VerifyBatch(keys, hashes, sigs) {
		t.Fatal("signature set failed batch verification")
	}

	// corrupt one key/hash/sig and check that verification fails
	keys[0][0] ^= 1
	if VerifyBatch(keys, hashes, sigs) {
		t.Error("corrupted key passed batch verification")
	}
	keys[0][0] ^= 1
	hashes[0][0] ^= 1
	if VerifyBatch(keys, hashes, sigs) {
		t.Error("corrupted hash passed batch verification")
	}
	hashes[0][0] ^= 1
	sigs[0][0] ^= 1
	if VerifyBatch(keys, hashes, sigs) {
		t.Error("corrupted sig passed batch verification")
	}
}

func TestVerifySingleKeyBatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	hashes := make([][32]byte, 10)
	sigs := make([][]byte, len(hashes))
	for i := range sigs {
		hashes[i] = frand.Entropy256()
		sigs[i] = Sign(priv, hashes[i])
		if !Verify(pub, hashes[i], sigs[i]) {
			t.Fatal("individual sig failed verification")
		}
	}
	if !VerifySingleKeyBatch(pub, hashes, sigs) {
		t.Fatal("signature set failed batch verification")
	}

	// corrupt key/hash/sig and check that verification fails
	pub[0] ^= 1
	if VerifySingleKeyBatch(pub, hashes, sigs) {
		t.Error("corrupted key passed batch verification")
	}
	pub[0] ^= 1
	hashes[0][0] ^= 1
	if VerifySingleKeyBatch(pub, hashes, sigs) {
		t.Error("corrupted hash passed batch verification")
	}
	hashes[0][0] ^= 1
	sigs[0][0] ^= 1
	if VerifySingleKeyBatch(pub, hashes, sigs) {
		t.Error("corrupted sig passed batch verification")
	}
}

func BenchmarkVerifyBatch(b *testing.B) {
	for _, n := range []int{1, 8, 64, 1024} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			keys := make([]ed25519.PublicKey, n)
			hashes := make([][32]byte, len(keys))
			sigs := make([][]byte, len(keys))
			for i := range keys {
				pub, priv, _ := ed25519.GenerateKey(nil)
				keys[i] = pub
				hashes[i] = frand.Entropy256()
				sigs[i] = Sign(priv, hashes[i])
			}
			// NOTE: dividing by n so that metrics are per-signature
			for i := 0; i < b.N/n; i++ {
				if !VerifyBatch(keys, hashes, sigs) {
					b.Fatal("signature set failed batch verification")
				}
			}
		})
	}
}

func BenchmarkVerifySingleKeyBatch(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	for _, n := range []int{1, 8, 64, 1024} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			hashes := make([][32]byte, n)
			sigs := make([][]byte, n)
			for i := range sigs {
				hashes[i] = frand.Entropy256()
				sigs[i] = Sign(priv, hashes[i])
			}
			// NOTE: dividing by n so that metrics are per-signature
			for i := 0; i < b.N/n; i++ {
				if !VerifySingleKeyBatch(pub, hashes, sigs) {
					b.Fatal("signature set failed batch verification")
				}
			}
		})
	}
}
