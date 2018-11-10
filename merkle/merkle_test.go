package merkle

import (
	"bytes"
	"reflect"
	"testing"
	"unsafe"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/fastrand"
	"golang.org/x/crypto/blake2b"
	"lukechampine.com/us/renterhost"
)

func leafHash(seg []byte) crypto.Hash {
	return blake2b.Sum256(append([]byte{leafHashPrefix}, seg...))
}

func nodeHash(left, right crypto.Hash) crypto.Hash {
	return blake2b.Sum256(append([]byte{nodeHashPrefix}, append(left[:], right[:]...)...))
}

func refSectorRoot(sector *[renterhost.SectorSize]byte) crypto.Hash {
	roots := make([]crypto.Hash, SegmentsPerSector)
	for i := range roots {
		roots[i] = leafHash(sector[i*LeafSize:][:LeafSize])
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

func TestSectorRoot(t *testing.T) {
	// test some known roots
	var sector [renterhost.SectorSize]byte
	if SectorRoot(&sector).String() != "50ed59cecd5ed3ca9e65cec0797202091dbba45272dafa3faa4e27064eedd52c" {
		t.Error("wrong Merkle root for empty sector")
	}
	sector[0] = 1
	if SectorRoot(&sector).String() != "8c20a2c90a733a5139cc57e45755322e304451c3434b0c0a0aad87f2f89a44ab" {
		t.Error("wrong Merkle root for sector[0] = 1")
	}
	sector[0] = 0
	sector[renterhost.SectorSize-1] = 1
	if SectorRoot(&sector).String() != "d0ab6691d76750618452e920386e5f6f98fdd1219a70a06f06ef622ac6c6373c" {
		t.Error("wrong Merkle root for sector[renterhost.SectorSize-1] = 1")
	}

	// test some random roots against a reference implementation
	for i := 0; i < 5; i++ {
		fastrand.Read(sector[:])
		if SectorRoot(&sector) != refSectorRoot(&sector) {
			t.Error("SectorRoot does not match reference implementation")
		}
	}

	// SectorRoot should not allocate
	allocs := testing.AllocsPerRun(10, func() {
		_ = SectorRoot(&sector)
	})
	if allocs > 0 {
		t.Error("expected SectorRoot to allocate 0 times, got", allocs)
	}
}

func BenchmarkSectorRoot(b *testing.B) {
	b.ReportAllocs()
	var sector [renterhost.SectorSize]byte
	for i := 0; i < b.N; i++ {
		_ = SectorRoot(&sector)
	}
}

func TestMetaRoot(t *testing.T) {
	// test some known roots
	if MetaRoot(nil) != (crypto.Hash{}) {
		t.Error("wrong cached Merkle root for empty stack")
	}
	roots := make([]crypto.Hash, 1)
	fastrand.Read(roots[0][:])
	if MetaRoot(roots) != roots[0] {
		t.Error("wrong cached Merkle root for single root")
	}
	roots = make([]crypto.Hash, 32)
	if MetaRoot(roots).String() != "1c23727030051d1bba1c887273addac2054afbd6926daddef6740f4f8bf1fb7f" {
		t.Error("wrong cached Merkle root for 32 empty roots")
	}
	roots[0][0] = 1
	if MetaRoot(roots).String() != "c5da05749139505704ea18a5d92d46427f652ac79c5f5712e4aefb68e20dffb8" {
		t.Error("wrong cached Merkle root for roots[0][0] = 1")
	}

	// test some random roots against a reference implementation
	for i := 0; i < 5; i++ {
		for j := range roots {
			fastrand.Read(roots[j][:])
		}
		if MetaRoot(roots) != recNodeRoot(roots) {
			t.Error("MetaRoot does not match reference implementation")
		}
	}

	// test an odd number of roots
	roots = roots[:5]
	refRoot := recNodeRoot([]crypto.Hash{recNodeRoot(roots[:4]), roots[4]})
	if MetaRoot(roots) != refRoot {
		t.Error("MetaRoot does not match reference implementation")
	}

	allocs := testing.AllocsPerRun(10, func() {
		_ = MetaRoot(roots)
	})
	if allocs > 0 {
		t.Error("expected MetaRoot to allocate 0 times, got", allocs)
	}
}

func BenchmarkMetaRoot1TB(b *testing.B) {
	const sectorsPerTerabyte = 262144
	b.ReportAllocs()
	roots := make([]crypto.Hash, sectorsPerTerabyte)
	for i := 0; i < b.N; i++ {
		_ = MetaRoot(roots)
	}
}

func TestStack(t *testing.T) {
	var s Stack

	// test some known roots
	if s.Root() != (crypto.Hash{}) {
		t.Error("wrong Stack root for empty stack")
	}

	roots := make([]crypto.Hash, 32)
	for _, root := range roots {
		s.AppendLeafHash(root)
	}
	if s.Root().String() != "1c23727030051d1bba1c887273addac2054afbd6926daddef6740f4f8bf1fb7f" {
		t.Error("wrong Stack root for 32 empty roots")
	}

	s.Reset()
	roots[0][0] = 1
	for _, root := range roots {
		s.AppendLeafHash(root)
	}
	if s.Root().String() != "c5da05749139505704ea18a5d92d46427f652ac79c5f5712e4aefb68e20dffb8" {
		t.Error("wrong Stack root for roots[0][0] = 1")
	}

	// test some random roots against a reference implementation
	for i := 0; i < 5; i++ {
		s.Reset()
		for j := range roots {
			fastrand.Read(roots[j][:])
			s.AppendLeafHash(roots[j])
		}
		if s.Root() != recNodeRoot(roots) {
			t.Error("Stack root does not match reference implementation")
		}
	}

	// test an odd number of roots
	s.Reset()
	roots = roots[:5]
	for _, root := range roots {
		s.AppendLeafHash(root)
	}
	refRoot := recNodeRoot([]crypto.Hash{recNodeRoot(roots[:4]), roots[4]})
	if s.Root() != refRoot {
		t.Error("Stack root does not match reference implementation")
	}

	// test NumRoots
	if s.NumLeaves() != 5 {
		t.Error("wrong number of nodes reported:", s.NumLeaves())
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

	// test marshalling
	var buf bytes.Buffer
	if err := s.MarshalSia(&buf); err != nil {
		t.Fatal(err)
	}
	var s2 Stack
	if err := s2.UnmarshalSia(&buf); err != nil {
		t.Fatal(err)
	} else if s.Root() != s2.Root() {
		t.Fatal("Stacks differ after marshal+unmarshal")
	}
}

func BenchmarkStack1TB(b *testing.B) {
	const sectorsPerTerabyte = 262144
	b.ReportAllocs()
	var s Stack
	for i := 0; i < b.N; i++ {
		s.Reset()
		for j := 0; j < sectorsPerTerabyte; j++ {
			s.AppendLeafHash(crypto.Hash{})
		}
	}
}

func TestBuildVerifyProof(t *testing.T) {
	// test some known proofs
	var sector [renterhost.SectorSize]byte
	fastrand.Read(sector[:])

	proof := BuildProof(&sector, 0, SegmentsPerSector, nil)
	if len(proof) != 0 {
		t.Error("BuildProof constructed an incorrect proof for the entire sector")
	}

	proof = BuildProof(&sector, 0, 1, nil)
	hash := leafHash(sector[:64])
	for i := range proof {
		hash = nodeHash(hash, proof[i])
	}
	if hash != SectorRoot(&sector) {
		t.Error("BuildProof constructed an incorrect proof for the first segment")
	} else if !VerifyProof(proof, sector[:64], 0, 1, hash) {
		t.Error("VerifyProof failed to verify a known correct proof")
	}

	proof = BuildProof(&sector, SegmentsPerSector-1, SegmentsPerSector, nil)
	hash = leafHash(sector[len(sector)-64:])
	for i := range proof {
		hash = nodeHash(proof[len(proof)-i-1], hash)
	}
	if hash != SectorRoot(&sector) {
		t.Error("BuildProof constructed an incorrect proof for the last segment")
	} else if !VerifyProof(proof, sector[len(sector)-64:], SegmentsPerSector-1, SegmentsPerSector, hash) {
		t.Error("VerifyProof failed to verify a known correct proof")
	}

	proof = BuildProof(&sector, 10, 11, nil)
	hash = leafHash(sector[10*64:][:64])
	hash = nodeHash(hash, proof[2])
	hash = nodeHash(proof[1], hash)
	hash = nodeHash(hash, proof[3])
	hash = nodeHash(proof[0], hash)
	for i := 4; i < len(proof); i++ {
		hash = nodeHash(hash, proof[i])
	}
	if hash != SectorRoot(&sector) {
		t.Error("BuildProof constructed an incorrect proof for a middle segment")
	} else if !VerifyProof(proof, sector[10*64:11*64], 10, 11, hash) {
		t.Error("VerifyProof failed to verify a known correct proof")
	}

	// this is the largest possible proof
	midl, midr := SegmentsPerSector/2-1, SegmentsPerSector/2+1
	proof = BuildProof(&sector, midl, midr, nil)
	left := leafHash(sector[midl*64:][:64])
	for i := 0; i < len(proof)/2; i++ {
		left = nodeHash(proof[len(proof)/2-i-1], left)
	}
	right := leafHash(sector[(midr-1)*64:][:64])
	for i := len(proof) / 2; i < len(proof); i++ {
		right = nodeHash(right, proof[i])
	}
	if nodeHash(left, right) != SectorRoot(&sector) {
		t.Error("BuildProof constructed an incorrect proof for worst-case inputs")
	} else if !VerifyProof(proof, sector[midl*64:midr*64], midl, midr, hash) {
		t.Error("VerifyProof failed to verify a known correct proof")
	}

	// test some random proofs against VerifyProof
	for i := 0; i < 5; i++ {
		start := fastrand.Intn(SegmentsPerSector - 1)
		end := start + fastrand.Intn(SegmentsPerSector-start)
		proof := BuildProof(&sector, start, end, nil)
		if !VerifyProof(proof, sector[start*LeafSize:end*LeafSize], start, end, SectorRoot(&sector)) {
			t.Errorf("BuildProof constructed an incorrect proof for range %v-%v", start, end)
		}
	}

	// test a proof with precomputed inputs
	leftRoots := make([]crypto.Hash, SegmentsPerSector/2)
	for i := range leftRoots {
		leftRoots[i] = leafHash(sector[i*LeafSize:][:LeafSize])
	}
	left = MetaRoot(leftRoots)
	precalc := func(i, j int) (h crypto.Hash) {
		if i == 0 && j == SegmentsPerSector/2 {
			h = left
		}
		return
	}
	proof = BuildProof(&sector, SegmentsPerSector-1, SegmentsPerSector, precalc)
	recalcProof := BuildProof(&sector, SegmentsPerSector-1, SegmentsPerSector, nil)
	if !reflect.DeepEqual(proof, recalcProof) {
		t.Fatal("precalc failed")
	}

	// test malformed inputs
	if VerifyProof(nil, make([]byte, LeafSize), 0, 1, crypto.Hash{}) {
		t.Error("VerifyProof verified an incorrect proof")
	}
	if VerifyProof([]crypto.Hash{{}}, sector[:], 0, SegmentsPerSector, crypto.Hash{}) {
		t.Error("VerifyProof verified an incorrect proof")
	}

	allocs := testing.AllocsPerRun(10, func() {
		_ = BuildProof(&sector, SegmentsPerSector-1, SegmentsPerSector, nil)
	})
	if allocs > 1 {
		t.Error("expected BuildProof to allocate one time, got", allocs)
	}

	proof = BuildProof(&sector, midl, midr, nil)
	allocs = testing.AllocsPerRun(10, func() {
		_ = VerifyProof(proof, sector[midl*64:midr*64], midl, midr, hash)
	})
	if allocs > 0 {
		t.Error("expected VerifyProof to allocate 0 times, got", allocs)
	}
}

func BenchmarkBuildProof(b *testing.B) {
	var sector [renterhost.SectorSize]byte
	fastrand.Read(sector[:])

	benchRange := func(start, end int) func(*testing.B) {
		return func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = BuildProof(&sector, start, end, nil)
			}
		}
	}

	b.Run("single", benchRange(0, 1))
	b.Run("half", benchRange(0, SegmentsPerSector/2))
	b.Run("mid", benchRange(SegmentsPerSector/2, 1+SegmentsPerSector/2))
	b.Run("full", benchRange(0, SegmentsPerSector-1))
}

func BenchmarkBuildProofPrecalc(b *testing.B) {
	var sector [renterhost.SectorSize]byte
	fastrand.Read(sector[:])
	root := SectorRoot(&sector)

	// precalculate left-hand nodes to depth 4
	roots := make([]crypto.Hash, SegmentsPerSector)
	for i := range roots {
		roots[i] = leafHash(sector[i*LeafSize:][:LeafSize])
	}
	left := make([]crypto.Hash, 4)
	left[0], roots = MetaRoot(roots[:SegmentsPerSector/2]), roots[SegmentsPerSector/2:]
	left[1], roots = MetaRoot(roots[:SegmentsPerSector/4]), roots[SegmentsPerSector/4:]
	left[2], roots = MetaRoot(roots[:SegmentsPerSector/8]), roots[SegmentsPerSector/8:]
	left[3], roots = MetaRoot(roots[:SegmentsPerSector/16]), roots[SegmentsPerSector/16:]
	_ = roots
	precalc := func(i, j int) crypto.Hash {
		// pattern matching would be nice here
		switch {
		case i == 0 && (j-i) == SegmentsPerSector/2:
			return left[0]
		case i == SegmentsPerSector/2 && (j-i) == SegmentsPerSector/4:
			return left[1]
		case i == SegmentsPerSector/2+SegmentsPerSector/4 && (j-i) == SegmentsPerSector/8:
			return left[2]
		case i == SegmentsPerSector/2+SegmentsPerSector/4+SegmentsPerSector/8 && (j-i) == SegmentsPerSector/16:
			return left[3]
		}
		return crypto.Hash{}
	}

	benchRange := func(start, end int) func(*testing.B) {
		return func(b *testing.B) {
			b.ReportAllocs()
			proof := BuildProof(&sector, start, end, precalc)
			if !VerifyProof(proof, sector[start*LeafSize:end*LeafSize], start, end, root) {
				b.Fatal("precalculated roots are incorrect")
			}
			for i := 0; i < b.N; i++ {
				_ = BuildProof(&sector, start, end, precalc)
			}
		}
	}

	b.Run("single", benchRange(SegmentsPerSector-1, SegmentsPerSector))
	b.Run("sixteenth", benchRange(SegmentsPerSector-SegmentsPerSector/16, SegmentsPerSector))
}

func BenchmarkVerifyProof(b *testing.B) {
	var sector [renterhost.SectorSize]byte
	fastrand.Read(sector[:])
	root := SectorRoot(&sector)

	benchRange := func(start, end int) func(*testing.B) {
		proof := BuildProof(&sector, start, end, nil)
		proofSegs := sector[start*LeafSize : end*LeafSize]
		return func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = VerifyProof(proof, proofSegs, start, end, root)
			}
		}
	}

	b.Run("single", benchRange(0, 1))
	b.Run("half", benchRange(0, SegmentsPerSector/2))
	b.Run("mid", benchRange(SegmentsPerSector/2, 1+SegmentsPerSector/2))
	b.Run("full", benchRange(0, SegmentsPerSector-1))
}
