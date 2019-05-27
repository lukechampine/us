// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ed25519

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"lukechampine.com/us/ed25519/internal/edwards25519"
)

func generateKey() (PublicKey, PrivateKey) {
	seed := make([]byte, SeedSize)
	rand.Read(seed)
	priv := NewKeyFromSeed(seed)
	return priv.PublicKey(), priv
}

func TestUnmarshalMarshal(t *testing.T) {
	pub, _ := generateKey()

	var A edwards25519.ExtendedGroupElement
	var pubBytes [32]byte
	copy(pubBytes[:], pub)
	if !A.FromBytes(&pubBytes) {
		t.Fatalf("ExtendedGroupElement.FromBytes failed")
	}

	var pub2 [32]byte
	A.ToBytes(&pub2)

	if pubBytes != pub2 {
		t.Errorf("FromBytes(%v)->ToBytes does not round-trip, got %x\n", pubBytes, pub2)
	}
}

func TestSignVerify(t *testing.T) {
	public, private := generateKey()

	hash := crypto.Hash{0}
	sig := private.SignHash(hash)
	if !public.VerifyHash(hash, sig) {
		t.Errorf("valid signature rejected")
	}

	wrongHash := crypto.Hash{1}
	if public.VerifyHash(wrongHash, sig) {
		t.Errorf("signature of different message accepted")
	}
}

func TestGolden(t *testing.T) {
	privBytes, _ := hex.DecodeString("8ed7a797b9cea8a8370d419136bcdf683b759d2e3c6947f17e13e2485aa9d420b49f3a78b1c6a7fca8f3466f33bc0e929f01fba04306c2a7465f46c3759316d9")
	msg, _ := hex.DecodeString("a750c232933dc14b1184d86d8b4ce72e16d69744ba69818b6ac33b1d823bb2c3")
	sig, _ := hex.DecodeString("04266c033b91c1322ceb3446c901ffcf3cc40c4034e887c9597ca1893ba7330becbbd8b48142ef35c012c6ba51a66df9308cb6268ad6b1e4b03e70102495790b")

	priv := PrivateKey(privBytes)
	var hash crypto.Hash
	copy(hash[:], msg)
	if !bytes.Equal(sig, priv.SignHash(hash)) {
		t.Error("bad signature")
	} else if !priv.PublicKey().VerifyHash(hash, sig) {
		t.Error("signature failed to verify")
	}
}

func BenchmarkHashSigning(b *testing.B) {
	b.ReportAllocs()
	_, priv := generateKey()
	hash := sha256.Sum256([]byte("Hello, world!"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		priv.SignHash(hash)
	}
}

func BenchmarkHashVerification(b *testing.B) {
	b.ReportAllocs()
	pub, priv := generateKey()
	hash := sha256.Sum256([]byte("Hello, world!"))
	signature := priv.SignHash(hash)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pub.VerifyHash(hash, signature)
	}
}
