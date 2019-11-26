package renter

import (
	"bytes"
	"strings"
	"testing"

	"lukechampine.com/frand"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renterhost"
)

func TestEncryption(t *testing.T) {
	var m MetaIndex
	frand.Read(m.MasterKey[:])
	key := m.MasterKey
	nonce := make([]byte, 24)

	plaintext := []byte(strings.Repeat("test", 64))
	ciphertext := append([]byte(nil), plaintext...)
	key.XORKeyStream(ciphertext, nonce, 0)
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("encryption failed")
	}

	// decrypt starting at a segment offset
	off := merkle.SegmentSize * 2
	key.XORKeyStream(ciphertext[off:], nonce, 2)
	if !bytes.Equal(ciphertext[off:], plaintext[off:]) {
		t.Error("decryption failed")
	}
}

func BenchmarkEncryption(b *testing.B) {
	var key KeySeed
	data := make([]byte, renterhost.SectorSize)
	nonce := make([]byte, 24)
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		key.XORKeyStream(data, nonce, 0)
	}
}
