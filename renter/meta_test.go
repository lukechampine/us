package renter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"strings"
	"testing"

	"github.com/aead/chacha20"
	"github.com/aead/chacha20/chacha"
	"gitlab.com/NebulousLabs/fastrand"
	"golang.org/x/crypto/xts"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renterhost"
)

func TestEncryption(t *testing.T) {
	var m MetaIndex
	fastrand.Read(m.MasterKey[:])
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
	b.SkipNow()
	benchXTS := func(buf []byte) func(*testing.B) {
		return func(b *testing.B) {
			c, err := xts.NewCipher(aes.NewCipher, make([]byte, 64))
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(buf)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.Encrypt(buf, buf, 0)
			}
		}
	}

	benchAES := func(buf []byte) func(*testing.B) {
		return func(b *testing.B) {
			c, err := aes.NewCipher(make([]byte, 32))
			if err != nil {
				b.Fatal(err)
			}
			key := cipher.NewCTR(c, make([]byte, aes.BlockSize))
			b.SetBytes(int64(len(buf)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				key.XORKeyStream(buf, buf)
			}
		}
	}

	benchChaCha := func(buf []byte) func(*testing.B) {
		return func(b *testing.B) {
			key, err := chacha20.NewCipher(make([]byte, chacha.NonceSize), make([]byte, chacha.KeySize))
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(buf)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				key.XORKeyStream(buf, buf)
			}
		}
	}

	benchXChaCha := func(buf []byte) func(*testing.B) {
		return func(b *testing.B) {
			key, err := chacha.NewCipher(make([]byte, chacha.XNonceSize), make([]byte, chacha.KeySize), 20)
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(buf)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				key.XORKeyStream(buf, buf)
			}
		}
	}

	segment := make([]byte, merkle.SegmentSize)
	sector := make([]byte, renterhost.SectorSize)
	b.Run("XTS-segment", benchXTS(segment))
	b.Run("AES-segment", benchAES(segment))
	b.Run("ChaCha-segment", benchChaCha(segment))
	b.Run("XChaCha-segment", benchXChaCha(segment))
	b.Run("XTS-sector", benchXTS(sector))
	b.Run("AES-sector", benchAES(sector))
	b.Run("ChaCha-sector", benchChaCha(sector))
	b.Run("XChaCha-sector", benchXChaCha(sector))
}
