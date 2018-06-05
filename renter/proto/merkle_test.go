package proto

import (
	"testing"

	"github.com/NebulousLabs/Sia/crypto"
	"github.com/NebulousLabs/fastrand"
	"golang.org/x/crypto/blake2b"
)

func refSectorMerkleRoot(sector *[SectorSize]byte) crypto.Hash {
	roots := make([]crypto.Hash, SegmentsPerSector)
	for i := range roots {
		seg := append([]byte{leafHashPrefix}, sector[i*SegmentSize:][:SegmentSize]...)
		roots[i] = blake2b.Sum256(seg)
	}
	return recNodeRoot(roots)
}

func recNodeRoot(roots []crypto.Hash) crypto.Hash {
	if len(roots) == 1 {
		return roots[0]
	}
	left := recNodeRoot(roots[:len(roots)/2])
	right := recNodeRoot(roots[len(roots)/2:])
	return blake2b.Sum256(append([]byte{nodeHashPrefix}, append(left[:], right[:]...)...))
}

func TestSectorMerkleRoot(t *testing.T) {
	// test some known roots
	var sector [SectorSize]byte
	if SectorMerkleRoot(&sector).String() != "50ed59cecd5ed3ca9e65cec0797202091dbba45272dafa3faa4e27064eedd52c" {
		t.Error("wrong Merkle root for empty sector")
	}
	sector[0] = 1
	if SectorMerkleRoot(&sector).String() != "8c20a2c90a733a5139cc57e45755322e304451c3434b0c0a0aad87f2f89a44ab" {
		t.Error("wrong Merkle root for sector[0] = 1")
	}
	sector[0] = 0
	sector[SectorSize-1] = 1
	if SectorMerkleRoot(&sector).String() != "d0ab6691d76750618452e920386e5f6f98fdd1219a70a06f06ef622ac6c6373c" {
		t.Error("wrong Merkle root for sector[SectorSize-1] = 1")
	}

	// test some random roots against a reference implementation
	for i := 0; i < 5; i++ {
		fastrand.Read(sector[:])
		if SectorMerkleRoot(&sector) != refSectorMerkleRoot(&sector) {
			t.Error("SectorMerkleRoot does not match reference implementation")
		}
	}
}

func BenchmarkSectorMerkleRoot(b *testing.B) {
	b.ReportAllocs()
	var sector [SectorSize]byte
	fastrand.Read(sector[:])
	for i := 0; i < b.N; i++ {
		_ = SectorMerkleRoot(&sector)
	}
}

func TestCachedMerkleRoot(t *testing.T) {
	// test some known roots
	roots := make([]crypto.Hash, 1)
	fastrand.Read(roots[0][:])
	if CachedMerkleRoot(roots) != roots[0] {
		t.Error("wrong cached Merkle root for single root")
	}
	roots = make([]crypto.Hash, 32)
	if CachedMerkleRoot(roots).String() != "1c23727030051d1bba1c887273addac2054afbd6926daddef6740f4f8bf1fb7f" {
		t.Error("wrong cached Merkle root for 32 empty roots")
	}
	roots[0][0] = 1
	if CachedMerkleRoot(roots).String() != "c5da05749139505704ea18a5d92d46427f652ac79c5f5712e4aefb68e20dffb8" {
		t.Error("wrong cached Merkle root for roots[0][0] = 1")
	}

	// test some random roots against a reference implementation
	for i := 0; i < 5; i++ {
		for j := range roots {
			fastrand.Read(roots[j][:])
		}
		if CachedMerkleRoot(roots) != recNodeRoot(roots) {
			t.Error("CachedMerkleRoot does not match reference implementation")
		}
	}
}

func BenchmarkCachedMerkleRoot(b *testing.B) {
	b.ReportAllocs()
	roots := make([]crypto.Hash, 32)
	for i := range roots {
		fastrand.Read(roots[i][:])
	}
	for i := 0; i < b.N; i++ {
		_ = CachedMerkleRoot(roots)
	}
}
