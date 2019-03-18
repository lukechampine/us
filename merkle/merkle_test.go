package merkle

import (
	"reflect"
	"testing"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/fastrand"
	"golang.org/x/crypto/blake2b"
	"lukechampine.com/us/renterhost"
)

func TestProofSize(t *testing.T) {
	tests := []struct {
		n, start, end int
		exp           int
	}{
		{9, 8, 9, 1},
		{10, 8, 9, 2},
		{10, 8, 10, 1},
		{11, 8, 9, 3},
		{11, 8, 10, 2},
		{11, 8, 11, 1},
		{12, 8, 9, 3},
		{12, 8, 10, 2},
		{12, 8, 11, 2},
		{12, 8, 12, 1},
		{13, 8, 9, 4},
		{13, 8, 10, 3},
		{13, 8, 11, 3},
		{13, 8, 12, 2},
		{13, 8, 13, 1},
		{14, 8, 9, 4},
		{14, 8, 10, 3},
		{14, 8, 11, 3},
		{14, 8, 12, 2},
		{14, 8, 13, 2},
		{14, 8, 14, 1},
	}
	for _, test := range tests {
		if s := ProofSize(test.n, test.start, test.end); s != test.exp {
			t.Errorf("expected ProofSize(%v, %v, %v) == %v, got %v", test.n, test.start, test.end, test.exp, s)
		}
	}
}

func leafHash(seg []byte) crypto.Hash {
	return blake2b.Sum256(append([]byte{leafHashPrefix}, seg...))
}

func nodeHash(left, right crypto.Hash) crypto.Hash {
	return blake2b.Sum256(append([]byte{nodeHashPrefix}, append(left[:], right[:]...)...))
}

func refSectorRoot(sector *[renterhost.SectorSize]byte) crypto.Hash {
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
	allocs := testing.AllocsPerRun(5, func() {
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
	var s stack

	// test some known roots
	if s.root() != (crypto.Hash{}) {
		t.Error("wrong Stack root for empty stack")
	}

	roots := make([]crypto.Hash, 32)
	for _, root := range roots {
		s.insertNodeHash(root, 0)
	}
	if s.root().String() != "1c23727030051d1bba1c887273addac2054afbd6926daddef6740f4f8bf1fb7f" {
		t.Error("wrong Stack root for 32 empty roots")
	}

	s.reset()
	roots[0][0] = 1
	for _, root := range roots {
		s.insertNodeHash(root, 0)
	}
	if s.root().String() != "c5da05749139505704ea18a5d92d46427f652ac79c5f5712e4aefb68e20dffb8" {
		t.Error("wrong Stack root for roots[0][0] = 1")
	}

	// test some random roots against a reference implementation
	for i := 0; i < 5; i++ {
		s.reset()
		for j := range roots {
			fastrand.Read(roots[j][:])
			s.insertNodeHash(roots[j], 0)
		}
		if s.root() != recNodeRoot(roots) {
			t.Error("Stack root does not match reference implementation")
		}
	}

	// test an odd number of roots
	s.reset()
	roots = roots[:5]
	for _, root := range roots {
		s.insertNodeHash(root, 0)
	}
	refRoot := recNodeRoot([]crypto.Hash{recNodeRoot(roots[:4]), roots[4]})
	if s.root() != refRoot {
		t.Error("Stack root does not match reference implementation")
	}
}

func BenchmarkStack1TB(b *testing.B) {
	const sectorsPerTerabyte = 262144
	b.ReportAllocs()
	var s stack
	for i := 0; i < b.N; i++ {
		s.reset()
		for j := 0; j < sectorsPerTerabyte; j++ {
			s.insertNodeHash(crypto.Hash{}, 0)
		}
	}
}

func TestBuildVerifyProof(t *testing.T) {
	// test some known proofs
	var sector [renterhost.SectorSize]byte
	fastrand.Read(sector[:])
	sectorRoot := SectorRoot(&sector)
	segmentRoots := make([]crypto.Hash, SegmentsPerSector)
	for i := range segmentRoots {
		segmentRoots[i] = leafHash(sector[i*SegmentSize:][:SegmentSize])
	}

	proof := BuildProof(&sector, 0, SegmentsPerSector, nil)
	if len(proof) != 0 {
		t.Error("BuildProof constructed an incorrect proof for the entire sector")
	}

	proof = BuildProof(&sector, 0, 1, nil)
	hash := leafHash(sector[:64])
	for i := range proof {
		hash = nodeHash(hash, proof[i])
	}
	if hash != sectorRoot {
		t.Error("BuildProof constructed an incorrect proof for the first segment")
	} else if !VerifyProof(proof, sector[:64], 0, 1, hash) {
		t.Error("VerifyProof failed to verify a known correct proof")
	}

	proof = BuildProof(&sector, SegmentsPerSector-1, SegmentsPerSector, nil)
	hash = leafHash(sector[len(sector)-64:])
	for i := range proof {
		hash = nodeHash(proof[len(proof)-i-1], hash)
	}
	if hash != sectorRoot {
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
	if hash != sectorRoot {
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
	if nodeHash(left, right) != sectorRoot {
		t.Error("BuildProof constructed an incorrect proof for worst-case inputs")
	} else if !VerifyProof(proof, sector[midl*64:midr*64], midl, midr, hash) {
		t.Error("VerifyProof failed to verify a known correct proof")
	}

	// test some random proofs against VerifyProof
	for i := 0; i < 5; i++ {
		start := fastrand.Intn(SegmentsPerSector - 1)
		end := start + fastrand.Intn(SegmentsPerSector-start)
		proof := BuildProof(&sector, start, end, nil)
		if !VerifyProof(proof, sector[start*SegmentSize:end*SegmentSize], start, end, sectorRoot) {
			t.Errorf("BuildProof constructed an incorrect proof for range %v-%v", start, end)
		}
	}

	// test a proof with precomputed inputs
	leftRoots := make([]crypto.Hash, SegmentsPerSector/2)
	for i := range leftRoots {
		leftRoots[i] = leafHash(sector[i*SegmentSize:][:SegmentSize])
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
	if VerifyProof(nil, make([]byte, SegmentSize), 0, 1, crypto.Hash{}) {
		t.Error("VerifyProof verified an incorrect proof")
	}
	if VerifyProof([]crypto.Hash{{}}, sector[:], 0, SegmentsPerSector, crypto.Hash{}) {
		t.Error("VerifyProof verified an incorrect proof")
	}

	allocs := testing.AllocsPerRun(5, func() {
		_ = BuildProof(&sector, 10, SegmentsPerSector-10, nil)
	})
	if allocs > 1 {
		t.Error("expected BuildProof to allocate one time, got", allocs)
	}

	proof = BuildProof(&sector, midl, midr, nil)
	allocs = testing.AllocsPerRun(5, func() {
		_ = VerifyProof(proof, sector[midl*64:midr*64], midl, midr, hash)
	})
	if allocs > 0 {
		t.Error("expected VerifyProof to allocate 0 times, got", allocs)
	}
}

func TestBuildVerifySectorRangeProof(t *testing.T) {
	// test some known proofs
	sectorRoots := make([]crypto.Hash, 16)
	for i := range sectorRoots {
		fastrand.Read(sectorRoots[i][:])
	}
	metaRoot := MetaRoot(sectorRoots)

	proof := BuildSectorRangeProof(sectorRoots, 0, len(sectorRoots))
	if len(proof) != 0 {
		t.Error("BuildSectorRangeProof constructed an incorrect proof for the entire tree")
	} else if !VerifySectorRangeProof(proof, sectorRoots, 0, len(sectorRoots), len(sectorRoots), metaRoot) {
		t.Error("VerifySectorRangeProof failed to verify a valid proof for the entire tree")
	}

	proof = BuildSectorRangeProof(sectorRoots[:2], 0, 1)
	hash := nodeHash(sectorRoots[0], proof[0])
	if hash != MetaRoot(sectorRoots[:2]) {
		t.Error("BuildSectorRangeProof constructed an incorrect proof for the first sector")
	} else if !VerifySectorRangeProof(proof, sectorRoots[0:1], 0, 1, 2, MetaRoot(sectorRoots[:2])) {
		t.Fatal("VerifySectorRangeProof failed to verify a valid proof for the first sector")
	}

	proof = BuildSectorRangeProof(sectorRoots[:4], 0, 2)
	hash = nodeHash(sectorRoots[0], sectorRoots[1])
	hash = nodeHash(hash, proof[0])
	if hash != MetaRoot(sectorRoots[:4]) {
		t.Error("BuildSectorRangeProof constructed an incorrect proof for the first two sectors")
	} else if !VerifySectorRangeProof(proof, sectorRoots[0:2], 0, 2, 4, MetaRoot(sectorRoots[:4])) {
		t.Error("VerifySectorRangeProof failed to verify a valid proof for the first two sectors")
	}

	proof = BuildSectorRangeProof(sectorRoots[:5], 0, 2)
	hash = nodeHash(sectorRoots[0], sectorRoots[1])
	hash = nodeHash(hash, proof[0])
	hash = nodeHash(hash, proof[1])
	if hash != MetaRoot(sectorRoots[:5]) {
		t.Error("BuildSectorRangeProof constructed an incorrect proof for the first two sectors")
	} else if !VerifySectorRangeProof(proof, sectorRoots[0:2], 0, 2, 5, MetaRoot(sectorRoots[:5])) {
		t.Error("VerifySectorRangeProof failed to verify a valid proof for the first two sectors")
	}

	// this is the largest possible proof
	proof = BuildSectorRangeProof(sectorRoots, 7, 9)
	left := sectorRoots[7]
	left = nodeHash(proof[2], left)
	left = nodeHash(proof[1], left)
	left = nodeHash(proof[0], left)
	right := sectorRoots[8]
	right = nodeHash(right, proof[3])
	right = nodeHash(right, proof[4])
	right = nodeHash(right, proof[5])
	hash = nodeHash(left, right)
	if hash != MetaRoot(sectorRoots) {
		t.Error("BuildProof constructed an incorrect proof for worst-case inputs")
	} else if !VerifySectorRangeProof(proof, sectorRoots[7:9], 7, 9, len(sectorRoots), metaRoot) {
		t.Error("VerifySectorRangeProof failed to verify a valid proof for worst-case inputs")
	}

	// build/verify all possible proofs in a 9-leaf tree
	metaRoot9 := MetaRoot(sectorRoots[:9])
	for start := 0; start < 9; start++ {
		for end := start + 1; end <= 9; end++ {
			proof := BuildSectorRangeProof(sectorRoots[:9], start, end)
			if !VerifySectorRangeProof(proof, sectorRoots[start:end], start, end, 9, metaRoot9) {
				t.Errorf("BuildProof constructed an incorrect proof for range %v-%v", start, end)
			}
		}
	}

	// test malformed inputs
	if VerifySectorRangeProof([]crypto.Hash{{}}, []crypto.Hash{{}}, 0, 1, 2, crypto.Hash{}) {
		t.Error("VerifySectorRangeProof verified an incorrect proof")
	}

	allocs := testing.AllocsPerRun(5, func() {
		_ = BuildSectorRangeProof(sectorRoots, 0, 1)
	})
	if allocs > 1 {
		t.Error("expected BuildSectorRangeProof to allocate one time, got", allocs)
	}

	proof = BuildSectorRangeProof(sectorRoots, 7, 9)
	allocs = testing.AllocsPerRun(5, func() {
		_ = VerifySectorRangeProof(proof, sectorRoots[7:9], 7, 9, len(sectorRoots), metaRoot)
	})
	if allocs > 0 {
		t.Error("expected VerifySectorRangeProof to allocate 0 times, got", allocs)
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
		roots[i] = leafHash(sector[i*SegmentSize:][:SegmentSize])
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
			if !VerifyProof(proof, sector[start*SegmentSize:end*SegmentSize], start, end, root) {
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
		proofSegs := sector[start*SegmentSize : end*SegmentSize]
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

func TestBuildVerifyDiffProof(t *testing.T) {
	const numSectors = 12
	sectorRoots := make([]crypto.Hash, numSectors)
	for i := range sectorRoots {
		fastrand.Read(sectorRoots[i][:])
	}
	oldRoot := MetaRoot(sectorRoots)

	var newSector12, newSector13 [renterhost.SectorSize]byte
	fastrand.Read(newSector12[:])
	fastrand.Read(newSector13[:])
	actions := []renterhost.RPCWriteAction{
		{Type: renterhost.RPCWriteActionSwap, A: 6, B: 11},
		{Type: renterhost.RPCWriteActionTrim, A: 1},
		{Type: renterhost.RPCWriteActionSwap, A: 7, B: 10},
		{Type: renterhost.RPCWriteActionAppend, Data: newSector12[:]},
		{Type: renterhost.RPCWriteActionAppend, Data: newSector13[:]},
	}
	treeHashes, leafHashes := BuildDiffProof(actions, sectorRoots)

	// verify the proof by manually calculating the old root
	if oldRoot != nodeHash(
		nodeHash(
			treeHashes[0],
			nodeHash(
				treeHashes[1],
				nodeHash(
					leafHashes[0],
					leafHashes[1],
				),
			),
		),
		nodeHash(
			treeHashes[2],
			nodeHash(
				leafHashes[2],
				leafHashes[3],
			),
		),
	) {
		t.Fatal("BuildDiffProof produced an invalid proof")
	}

	// then calculate the new root and verify the proof
	newRoot := MetaRoot([]crypto.Hash{
		sectorRoots[0], sectorRoots[1], sectorRoots[2], sectorRoots[3],
		sectorRoots[4], sectorRoots[5], sectorRoots[11], sectorRoots[10],
		sectorRoots[8], sectorRoots[9], sectorRoots[7], SectorRoot(&newSector12),
		SectorRoot(&newSector13),
	})

	if !VerifyDiffProof(actions, numSectors, treeHashes, leafHashes, oldRoot, newRoot) {
		t.Error("failed to verify proof produced by BuildDiffProof")
	}
}

func TestBuildVerifyDiffProofAppend(t *testing.T) {
	const numSectors = 15
	sectorRoots := make([]crypto.Hash, numSectors)
	for i := range sectorRoots {
		fastrand.Read(sectorRoots[i][:])
	}
	oldRoot := MetaRoot(sectorRoots)

	var newSector15, newSector16 [renterhost.SectorSize]byte
	fastrand.Read(newSector15[:])
	fastrand.Read(newSector16[:])
	actions := []renterhost.RPCWriteAction{
		{Type: renterhost.RPCWriteActionAppend, Data: newSector15[:]},
		{Type: renterhost.RPCWriteActionSwap, A: 3, B: 15},
		{Type: renterhost.RPCWriteActionAppend, Data: newSector16[:]},
	}
	treeHashes, leafHashes := BuildDiffProof(actions, sectorRoots)

	// verify the proof by manually calculating the old root
	if oldRoot != nodeHash(
		nodeHash(
			nodeHash(
				treeHashes[0],
				nodeHash(
					treeHashes[1],
					leafHashes[0],
				),
			),
			treeHashes[2],
		),
		nodeHash(
			treeHashes[3],
			nodeHash(
				treeHashes[4],
				treeHashes[5],
			),
		),
	) {
		t.Fatal("BuildDiffProof produced an invalid proof")
	}

	// then calculate the new root and verify the proof
	newRoot := MetaRoot([]crypto.Hash{
		sectorRoots[0], sectorRoots[1], sectorRoots[2], SectorRoot(&newSector15),
		sectorRoots[4], sectorRoots[5], sectorRoots[6], sectorRoots[7],
		sectorRoots[8], sectorRoots[9], sectorRoots[10], sectorRoots[11],
		sectorRoots[12], sectorRoots[13], sectorRoots[14], sectorRoots[3],
		SectorRoot(&newSector16),
	})

	if !VerifyDiffProof(actions, numSectors, treeHashes, leafHashes, oldRoot, newRoot) {
		t.Error("failed to verify proof produced by BuildDiffProof")
	}
}

func TestBuildVerifyDiffProofTrim(t *testing.T) {
	const numSectors = 15
	sectorRoots := make([]crypto.Hash, numSectors)
	for i := range sectorRoots {
		fastrand.Read(sectorRoots[i][:])
	}
	oldRoot := MetaRoot(sectorRoots)

	actions := []renterhost.RPCWriteAction{
		{Type: renterhost.RPCWriteActionSwap, A: 3, B: 14},
		{Type: renterhost.RPCWriteActionTrim, A: 2},
	}
	treeHashes, leafHashes := BuildDiffProof(actions, sectorRoots)

	// verify the proof by manually calculating the old root
	if oldRoot != nodeHash(
		nodeHash(
			nodeHash(
				treeHashes[0],
				nodeHash(
					treeHashes[1],
					leafHashes[0],
				),
			),
			treeHashes[2],
		),
		nodeHash(
			treeHashes[3],
			nodeHash(
				nodeHash(
					treeHashes[4],
					leafHashes[1],
				),
				leafHashes[2],
			),
		),
	) {
		t.Fatal("BuildDiffProof produced an invalid proof")
	}

	// then calculate the new root and verify the proof
	newRoot := MetaRoot([]crypto.Hash{
		sectorRoots[0], sectorRoots[1], sectorRoots[2], sectorRoots[14],
		sectorRoots[4], sectorRoots[5], sectorRoots[6], sectorRoots[7],
		sectorRoots[8], sectorRoots[9], sectorRoots[10], sectorRoots[11],
		sectorRoots[12],
	})

	if !VerifyDiffProof(actions, numSectors, treeHashes, leafHashes, oldRoot, newRoot) {
		t.Error("failed to verify proof produced by BuildDiffProof")
	}
}

func BenchmarkBuildDiffProof(b *testing.B) {
	const numSectors = 12
	sectorRoots := make([]crypto.Hash, numSectors)
	for i := range sectorRoots {
		fastrand.Read(sectorRoots[i][:])
	}

	var newSector12, newSector13 [renterhost.SectorSize]byte
	fastrand.Read(newSector12[:])
	fastrand.Read(newSector13[:])
	actions := []renterhost.RPCWriteAction{
		{Type: renterhost.RPCWriteActionSwap, A: 6, B: 11},
		{Type: renterhost.RPCWriteActionTrim, A: 1},
		{Type: renterhost.RPCWriteActionSwap, A: 7, B: 10},
		{Type: renterhost.RPCWriteActionAppend, Data: newSector12[:]},
		{Type: renterhost.RPCWriteActionAppend, Data: newSector13[:]},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = BuildDiffProof(actions, sectorRoots)
	}
}

func BenchmarkVerifyDiffProof(b *testing.B) {
	const numSectors = 12
	sectorRoots := make([]crypto.Hash, numSectors)
	for i := range sectorRoots {
		fastrand.Read(sectorRoots[i][:])
	}
	var newSector12, newSector13 [renterhost.SectorSize]byte
	fastrand.Read(newSector12[:])
	fastrand.Read(newSector13[:])
	actions := []renterhost.RPCWriteAction{
		{Type: renterhost.RPCWriteActionSwap, A: 6, B: 11},
		{Type: renterhost.RPCWriteActionTrim, A: 1},
		{Type: renterhost.RPCWriteActionSwap, A: 7, B: 10},
		{Type: renterhost.RPCWriteActionAppend, Data: newSector12[:]},
		{Type: renterhost.RPCWriteActionAppend, Data: newSector13[:]},
	}
	treeHashes, leafHashes := BuildDiffProof(actions, sectorRoots)

	oldRoot := MetaRoot(sectorRoots)
	newRoot := MetaRoot([]crypto.Hash{
		sectorRoots[0], sectorRoots[1], sectorRoots[2], sectorRoots[3],
		sectorRoots[4], sectorRoots[5], sectorRoots[11], sectorRoots[10],
		sectorRoots[8], sectorRoots[9], sectorRoots[7], SectorRoot(&newSector12),
		SectorRoot(&newSector13),
	})
	if !VerifyDiffProof(actions, numSectors, treeHashes, leafHashes, oldRoot, newRoot) {
		b.Fatal("failed to verify proof produced by BuildDiffProof")
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		VerifyDiffProof(actions, numSectors, treeHashes, leafHashes, oldRoot, newRoot)
	}
}
