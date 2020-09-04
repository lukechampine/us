package renter

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lukechampine.com/frand"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renterhost"
)

func TestEncryption(t *testing.T) {
	key := KeySeed(frand.Entropy256())
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

func BenchmarkWriteMetaFile(b *testing.B) {
	const numSlices = 250000 // 1TB of uploaded data
	hpk := hostdb.HostKeyFromPublicKey(make([]byte, 32))
	m := NewMetaFile(0660, numSlices*renterhost.SectorSize, []hostdb.HostPublicKey{hpk}, 1)
	m.Shards[0] = make([]SectorSlice, numSlices)
	for i := range m.Shards[0] {
		s := SectorSlice{
			SegmentIndex: uint32(frand.Uint64n(1024)),
			NumSegments:  uint32(frand.Uint64n(1024)),
		}
		s.MerkleRoot = frand.Entropy256()
		s.Nonce = frand.Entropy192()
		m.Shards[0][i] = s
	}
	path := filepath.Join(os.TempDir(), b.Name()+".usa")
	defer os.RemoveAll(path)
	b.ResetTimer()
	b.SetBytes(numSlices * SectorSliceSize * int64(len(m.Shards)))

	for i := 0; i < b.N; i++ {
		if err := WriteMetaFile(path, m); err != nil {
			b.Fatal(err)
		}
	}
}
