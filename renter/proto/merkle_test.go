package proto

import (
	"bytes"
	"reflect"
	"testing"
	"unsafe"

	"github.com/NebulousLabs/Sia/crypto"
	"github.com/NebulousLabs/fastrand"
	"github.com/dchest/blake2b"
)

func leafHash(seg []byte) crypto.Hash {
	return blake2b.Sum256(append([]byte{leafHashPrefix}, seg...))
}

func nodeHash(left, right crypto.Hash) crypto.Hash {
	return blake2b.Sum256(append([]byte{nodeHashPrefix}, append(left[:], right[:]...)...))
}

func refSectorMerkleRoot(sector *[SectorSize]byte) crypto.Hash {
	roots := make([]crypto.Hash, SegmentsPerSector)
	for i := range roots {
		roots[i] = leafHash(sector[i*SegmentSize:][:SegmentSize])
	}
	return recNodeRoot(roots)
}

func recNodeRoot(roots []crypto.Hash) crypto.Hash {
	if len(roots) == 1 {
		return roots[0]
	}
	return nodeHash(
		recNodeRoot(roots[:len(roots)/2]),
		recNodeRoot(roots[len(roots)/2:]),
	)
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
	if CachedMerkleRoot(nil) != (crypto.Hash{}) {
		t.Error("wrong cached Merkle root for empty stack")
	}
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

	// test an odd number of roots
	roots = roots[:5]
	refRoot := recNodeRoot([]crypto.Hash{recNodeRoot(roots[:4]), roots[4]})
	if CachedMerkleRoot(roots) != refRoot {
		t.Error("CachedMerkleRoot does not match reference implementation")
	}
}

func BenchmarkCachedMerkleRoot1TB(b *testing.B) {
	const sectorsPerTerabyte = 262144
	b.ReportAllocs()
	roots := make([]crypto.Hash, sectorsPerTerabyte)
	for i := 0; i < b.N; i++ {
		_ = CachedMerkleRoot(roots)
	}
}

func TestMerkleStack(t *testing.T) {
	var s MerkleStack

	// test some known roots
	if s.Root() != (crypto.Hash{}) {
		t.Error("wrong MerkleStack root for empty stack")
	}

	roots := make([]crypto.Hash, 32)
	for _, root := range roots {
		s.AppendNode(root)
	}
	if s.Root().String() != "1c23727030051d1bba1c887273addac2054afbd6926daddef6740f4f8bf1fb7f" {
		t.Error("wrong MerkleStack root for 32 empty roots")
	}

	s.Reset()
	roots[0][0] = 1
	for _, root := range roots {
		s.AppendNode(root)
	}
	if s.Root().String() != "c5da05749139505704ea18a5d92d46427f652ac79c5f5712e4aefb68e20dffb8" {
		t.Error("wrong MerkleStack root for roots[0][0] = 1")
	}

	// test some random roots against a reference implementation
	for i := 0; i < 5; i++ {
		s.Reset()
		for j := range roots {
			fastrand.Read(roots[j][:])
			s.AppendNode(roots[j])
		}
		if s.Root() != recNodeRoot(roots) {
			t.Error("MerkleStack root does not match reference implementation")
		}
	}

	// test an odd number of roots
	s.Reset()
	roots = roots[:5]
	for _, root := range roots {
		s.AppendNode(root)
	}
	refRoot := recNodeRoot([]crypto.Hash{recNodeRoot(roots[:4]), roots[4]})
	if s.Root() != refRoot {
		t.Error("MerkleStack root does not match reference implementation")
	}

	// test NumRoots
	if s.NumNodes() != 5 {
		t.Error("wrong number of nodes reported:", s.NumNodes())
	}

	// test ReadFrom
	s.Reset()
	rootsBytes := *(*[5 * crypto.HashSize]byte)(unsafe.Pointer(&roots[0]))
	n, err := s.ReadFrom(bytes.NewReader(rootsBytes[:]))
	if err != nil {
		t.Error("unexpected ReadFrom error:", err)
	} else if n != int64(len(rootsBytes)) {
		t.Error("wrong number of bytes read:", n)
	} else if s.Root() != refRoot {
		t.Error("wrong root after calling ReadFrom")
	}
}

func BenchmarkMerkleStack1TB(b *testing.B) {
	const sectorsPerTerabyte = 262144
	b.ReportAllocs()
	var s MerkleStack
	for i := 0; i < b.N; i++ {
		s.Reset()
		for j := 0; j < sectorsPerTerabyte; j++ {
			s.AppendNode(crypto.Hash{})
		}
	}
}

func TestBuildVerifyMerkleProof(t *testing.T) {
	// test some known proofs
	var sector [SectorSize]byte
	fastrand.Read(sector[:])

	proof := BuildMerkleProof(&sector, 0, SegmentsPerSector, nil)
	if len(proof) != 0 {
		t.Error("BuildMerkleProof constructed an incorrect proof for the entire sector")
	}

	proof = BuildMerkleProof(&sector, 0, 1, nil)
	hash := leafHash(sector[:64])
	for i := range proof {
		hash = nodeHash(hash, proof[i])
	}
	if hash != SectorMerkleRoot(&sector) {
		t.Error("BuildMerkleProof constructed an incorrect proof for the first segment")
	} else if !VerifyMerkleProof(proof, sector[:64], 0, 1, hash) {
		t.Error("VerifyMerkleProof failed to verify a known correct proof")
	}

	proof = BuildMerkleProof(&sector, SegmentsPerSector-1, SegmentsPerSector, nil)
	hash = leafHash(sector[len(sector)-64:])
	for i := range proof {
		hash = nodeHash(proof[len(proof)-i-1], hash)
	}
	if hash != SectorMerkleRoot(&sector) {
		t.Error("BuildMerkleProof constructed an incorrect proof for the last segment")
	} else if !VerifyMerkleProof(proof, sector[len(sector)-64:], SegmentsPerSector-1, SegmentsPerSector, hash) {
		t.Error("VerifyMerkleProof failed to verify a known correct proof")
	}

	proof = BuildMerkleProof(&sector, 10, 11, nil)
	hash = leafHash(sector[10*64:][:64])
	hash = nodeHash(hash, proof[2])
	hash = nodeHash(proof[1], hash)
	hash = nodeHash(hash, proof[3])
	hash = nodeHash(proof[0], hash)
	for i := 4; i < len(proof); i++ {
		hash = nodeHash(hash, proof[i])
	}
	if hash != SectorMerkleRoot(&sector) {
		t.Error("BuildMerkleProof constructed an incorrect proof for a middle segment")
	} else if !VerifyMerkleProof(proof, sector[10*64:11*64], 10, 11, hash) {
		t.Error("VerifyMerkleProof failed to verify a known correct proof")
	}

	// this is the largest possible proof
	proof = BuildMerkleProof(&sector, 32767, 32769, nil)
	left := leafHash(sector[32767*64:][:64])
	for i := 0; i < 15; i++ {
		left = nodeHash(proof[15-i-1], left)
	}
	right := leafHash(sector[32768*64:][:64])
	for i := 15; i < len(proof); i++ {
		right = nodeHash(right, proof[i])
	}
	if nodeHash(left, right) != SectorMerkleRoot(&sector) {
		t.Error("BuildMerkleProof constructed an incorrect proof for worst-case inputs")
	} else if !VerifyMerkleProof(proof, sector[32767*64:32769*64], 32767, 32769, hash) {
		t.Error("VerifyMerkleProof failed to verify a known correct proof")
	}

	// test some random proofs against VerifyMerkleProof
	for i := 0; i < 5; i++ {
		start := fastrand.Intn(SegmentsPerSector - 1)
		end := start + fastrand.Intn(SegmentsPerSector-start)
		proof := BuildMerkleProof(&sector, start, end, nil)
		if !VerifyMerkleProof(proof, sector[start*SegmentSize:end*SegmentSize], start, end, SectorMerkleRoot(&sector)) {
			t.Errorf("BuildMerkleProof constructed an incorrect proof for range %v-%v", start, end)
		}
	}

	// test a proof with precomputed inputs
	leftRoots := make([]crypto.Hash, SegmentsPerSector/2)
	for i := range leftRoots {
		leftRoots[i] = leafHash(sector[i*SegmentSize:][:SegmentSize])
	}
	left = CachedMerkleRoot(leftRoots)
	precalc := func(i, j int) (h crypto.Hash) {
		if i == 0 && j == SegmentsPerSector/2 {
			h = left
		}
		return
	}
	proof = BuildMerkleProof(&sector, SegmentsPerSector-1, SegmentsPerSector, precalc)
	recalcProof := BuildMerkleProof(&sector, SegmentsPerSector-1, SegmentsPerSector, nil)
	if !reflect.DeepEqual(proof, recalcProof) {
		t.Fatal("precalc failed")
	}

	// test malformed inputs
	if VerifyMerkleProof(nil, make([]byte, SegmentSize), 0, 1, crypto.Hash{}) {
		t.Error("VerifyMerkleProof verified an incorrect proof")
	}
	if VerifyMerkleProof([]crypto.Hash{{}}, sector[:], 0, SegmentsPerSector, crypto.Hash{}) {
		t.Error("VerifyMerkleProof verified an incorrect proof")
	}
}

func BenchmarkBuildMerkleProof(b *testing.B) {
	var sector [SectorSize]byte
	fastrand.Read(sector[:])

	benchRange := func(start, end int) func(*testing.B) {
		return func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = BuildMerkleProof(&sector, start, end, nil)
			}
		}
	}

	b.Run("single", benchRange(0, 1))
	b.Run("half", benchRange(0, SegmentsPerSector/2))
	b.Run("mid", benchRange(SegmentsPerSector/2, 1+SegmentsPerSector/2))
}

func BenchmarkBuildMerkleProofPrecalc(b *testing.B) {
	var sector [SectorSize]byte
	fastrand.Read(sector[:])
	root := SectorMerkleRoot(&sector)

	roots := make([]crypto.Hash, SegmentsPerSector)
	for i := range roots {
		roots[i] = leafHash(sector[i*SegmentSize:][:SegmentSize])
	}
	left := make([]crypto.Hash, 4)
	left[0], roots = CachedMerkleRoot(roots[:SegmentsPerSector/2]), roots[SegmentsPerSector/2:]
	left[1], roots = CachedMerkleRoot(roots[:SegmentsPerSector/4]), roots[SegmentsPerSector/4:]
	left[2], roots = CachedMerkleRoot(roots[:SegmentsPerSector/8]), roots[SegmentsPerSector/8:]
	left[3], roots = CachedMerkleRoot(roots[:SegmentsPerSector/16]), roots[SegmentsPerSector/16:]
	precalc := func(i, j int) crypto.Hash {
		if (j - i) == SegmentsPerSector/2 {
			return left[0]
		}
		if (j - i) == SegmentsPerSector/4 {
			return left[1]
		}
		if (j - i) == SegmentsPerSector/8 {
			return left[2]
		}
		if (j - i) == SegmentsPerSector/16 {
			return left[3]
		}
		return crypto.Hash{}
	}

	benchRange := func(start, end int) func(*testing.B) {
		return func(b *testing.B) {
			b.ReportAllocs()
			proof := BuildMerkleProof(&sector, start, end, precalc)
			if !VerifyMerkleProof(proof, sector[start*SegmentSize:end*SegmentSize], start, end, root) {
				b.Fatal("precalculated roots are incorrect")
			}
			for i := 0; i < b.N; i++ {
				_ = BuildMerkleProof(&sector, start, end, precalc)
			}
		}
	}

	b.Run("single", benchRange(SegmentsPerSector-1, SegmentsPerSector))
	b.Run("sixteenth", benchRange(SegmentsPerSector-SegmentsPerSector/16, SegmentsPerSector))
}

func BenchmarkVerifyMerkleProof(b *testing.B) {
	var sector [SectorSize]byte
	fastrand.Read(sector[:])
	root := SectorMerkleRoot(&sector)

	benchRange := func(start, end int) func(*testing.B) {
		proof := BuildMerkleProof(&sector, start, end, nil)
		proofSegs := sector[start*SegmentSize : end*SegmentSize]
		return func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = VerifyMerkleProof(proof, proofSegs, start, end, root)
			}
		}
	}

	b.Run("single", benchRange(0, 1))
	b.Run("half", benchRange(0, SegmentsPerSector/2))
	b.Run("mid", benchRange(SegmentsPerSector/2, 1+SegmentsPerSector/2))
}
