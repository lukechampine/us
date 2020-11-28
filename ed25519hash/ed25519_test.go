package ed25519hash

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"gitlab.com/NebulousLabs/Sia/crypto"
)

func TestSignVerify(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)

	hash := crypto.Hash{0}
	sig := Sign(private, hash)
	if !Verify(public, hash, sig) {
		t.Errorf("valid signature rejected")
	}

	wrongHash := crypto.Hash{1}
	if Verify(public, wrongHash, sig) {
		t.Errorf("signature of different message accepted")
	}
}

func TestGolden(t *testing.T) {
	privBytes, _ := hex.DecodeString("8ed7a797b9cea8a8370d419136bcdf683b759d2e3c6947f17e13e2485aa9d420b49f3a78b1c6a7fca8f3466f33bc0e929f01fba04306c2a7465f46c3759316d9")
	msg, _ := hex.DecodeString("a750c232933dc14b1184d86d8b4ce72e16d69744ba69818b6ac33b1d823bb2c3")
	sig, _ := hex.DecodeString("04266c033b91c1322ceb3446c901ffcf3cc40c4034e887c9597ca1893ba7330becbbd8b48142ef35c012c6ba51a66df9308cb6268ad6b1e4b03e70102495790b")

	priv := ed25519.PrivateKey(privBytes)
	var hash crypto.Hash
	copy(hash[:], msg)
	if !bytes.Equal(sig, Sign(priv, hash)) {
		t.Error("bad signature")
	} else if !Verify(ExtractPublicKey(priv), hash, sig) {
		t.Error("signature failed to verify")
	}
}

func BenchmarkHashSigning(b *testing.B) {
	b.ReportAllocs()
	_, priv, _ := ed25519.GenerateKey(nil)
	hash := crypto.Hash{1}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign(priv, hash)
	}
}

func BenchmarkHashVerification(b *testing.B) {
	b.ReportAllocs()
	pub, priv, _ := ed25519.GenerateKey(nil)
	hash := crypto.Hash{1}
	signature := Sign(priv, hash)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(pub, hash, signature)
	}
}
