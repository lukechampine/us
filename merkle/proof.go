package merkle

import (
	"math/bits"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"lukechampine.com/us/renterhost"
)

// ProofSize returns the size of a Merkle proof for the leaf range [start, end)
// within a tree containing n leaves.
func ProofSize(n, start, end int) int {
	// In a binary tree, the path from a leaf to the root is encoded in the
	// binary representation of the leaf index: 1s correspond to "left"
	// branches, and 0s correspond to "right" branches. Thus, for balanced
	// trees, the proof size is the number of 1s in start plus the number of 0s
	// in (end-1). However, if the tree is not balanced, some "right" branches
	// will be missing for certain indices.
	//
	// To compensate for this, we compare the "path" of (end-1) to the "path" of
	// (n-1), moving from leaves to root. After the paths converge, we know that
	// any subsequent "right" branches are not actually present in the tree and
	// should be ignored.
	leftHashes := bits.OnesCount(uint(start))
	pathMask := 1<<uint(bits.Len(uint((end-1)^(n-1)))) - 1
	rightHashes := bits.OnesCount(^uint(end-1) & uint(pathMask))
	return leftHashes + rightHashes
}

// nextSubtreeSize returns the size of the subtree adjacent to start that does
// not overlap end.
func nextSubtreeSize(start, end int) int {
	ideal := bits.TrailingZeros(uint(start))
	max := bits.Len(uint(end-start)) - 1
	if ideal > max {
		return 1 << uint(max)
	}
	return 1 << uint(ideal)
}

// BuildProof constructs a proof for the segment range [start, end). If a non-
// nil precalc function is provided, it will be used to supply precalculated
// subtree Merkle roots. For example, if the root of the left half of the
// Merkle tree is precomputed, precalc should return it for i == 0 and j ==
// SegmentsPerSector/2. If a precalculated root is not available, precalc
// should return the zero hash.
func BuildProof(sector *[renterhost.SectorSize]byte, start, end int, precalc func(i, j int) crypto.Hash) []crypto.Hash {
	if start < 0 || end > SegmentsPerSector || start > end || start == end {
		panic("BuildProof: illegal proof range")
	}
	if precalc == nil {
		precalc = func(i, j int) (h crypto.Hash) { return }
	}

	// define a helper function for later
	var s Stack
	subtreeRoot := func(i, j int) crypto.Hash {
		s.Reset()
		for ; i < j; i++ {
			s.AppendLeafHash(s.leafHash(sector[i*SegmentSize:][:SegmentSize]))
		}
		return s.Root()
	}

	// we build the proof by recursively enumerating subtrees, left to right.
	// If a subtree is inside the segment range, we can skip it (because the
	// verifier has the segments); otherwise, we add its Merkle root to the
	// proof.
	//
	// NOTE: this operation might be a little tricky to understand because
	// it's a recursive function with side effects (appending to proof), but
	// this is the simplest way I was able to implement it. Namely, it has the
	// important advantage of being symmetrical to the Verify operation.
	proof := make([]crypto.Hash, 0, ProofSize(SegmentsPerSector, start, end))
	var rec func(int, int)
	rec = func(i, j int) {
		if i >= start && j <= end {
			// this subtree contains only data segments; skip it
		} else if j <= start || i >= end {
			// this subtree does not contain any data segments; add its Merkle
			// root to the proof. If we have a precalculated root, use that;
			// otherwise, calculate it from scratch.
			if h := precalc(i, j); h != (crypto.Hash{}) {
				proof = append(proof, h)
			} else {
				proof = append(proof, subtreeRoot(i, j))
			}
		} else {
			// this subtree partially overlaps the data segments; split it
			// into two subtrees and recurse on each
			mid := (i + j) / 2
			rec(i, mid)
			rec(mid, j)
		}
	}
	rec(0, SegmentsPerSector)
	return proof
}

// verifyProof verifies a proof produced by BuildProof.
func verifyProof(proof []crypto.Hash, subtreeRoot func(i, j int) crypto.Hash, start, end int, root crypto.Hash) bool {
	if len(proof) != ProofSize(SegmentsPerSector, start, end) {
		return false
	}

	// we verify the proof by recursively enumerating subtrees, left to right,
	// and calculating their Merkle root. If the subtree is inside the segment
	// range, then we calculate its root by combining segRoots; if the subtree
	// is outside the segment range, its Merkle root should be the "next"
	// hash supplied in the proof set.
	//
	// NOTE: this operation might be a little tricky to understand because
	// it's a recursive function with side effects (popping hashes off the
	// proof set), but this is the simplest way I was able to implement it.
	// Namely, it has the important advantage of being symmetrical to the
	// Build operation.
	var s Stack
	var rec func(int, int) crypto.Hash
	rec = func(i, j int) crypto.Hash {
		if i >= start && j <= end {
			// this subtree contains only data segments; return their root
			return subtreeRoot(i, j)
		} else if j <= start || i >= end {
			// this subtree does not overlap with the data segments at all;
			// the root of this tree should be the next hash in the proof set.
			h := proof[0]
			proof = proof[1:]
			return h
		} else {
			// this subtree partially overlaps the data segments; split it
			// into two subtrees and recurse on each, joining their roots.
			mid := (i + j) / 2
			left := rec(i, mid)
			right := rec(mid, j)
			return s.nodeHash(left, right)
		}
	}
	return rec(0, SegmentsPerSector) == root
}

// VerifyProof verifies a proof produced by BuildProof. Only sector-sized
// proofs can be verified.
func VerifyProof(proof []crypto.Hash, segments []byte, start, end int, root crypto.Hash) bool {
	if len(segments)%SegmentSize != 0 {
		panic("VerifyProof: segments must be a multiple of SegmentSize")
	} else if len(segments) != (end-start)*SegmentSize {
		panic("VerifyProof: segments length does not match range")
	} else if start < 0 || end > SegmentsPerSector || start > end || start == end {
		panic("VerifyProof: illegal proof range")
	}

	var s Stack
	subtreeRoot := func(i, j int) crypto.Hash {
		s.Reset()
		for ; i < j; i++ {
			s.AppendLeafHash(s.leafHash(segments[(i-start)*SegmentSize:][:SegmentSize]))
		}
		return s.Root()
	}
	return verifyProof(proof, subtreeRoot, start, end, root)
}

// BuildSectorRangeProof constructs a proof for the sector range [start, end).
func BuildSectorRangeProof(sectorRoots []crypto.Hash, start, end int) []crypto.Hash {
	if start < 0 || end > len(sectorRoots) || start > end || start == end {
		panic("BuildSectorRangeProof: illegal proof range")
	}

	proof := make([]crypto.Hash, 0, ProofSize(len(sectorRoots), start, end))
	buildRange := func(i, j int) {
		for i < j {
			subtreeSize := nextSubtreeSize(i, j)
			proof = append(proof, MetaRoot(sectorRoots[i:][:subtreeSize]))
			i += subtreeSize
		}
	}
	buildRange(0, start)
	buildRange(end, len(sectorRoots))
	return proof
}

// VerifySectorRangeProof verifies a proof produced by BuildSectorRangeProof.
func VerifySectorRangeProof(proof []crypto.Hash, rangeRoots []crypto.Hash, start, end, numRoots int, root crypto.Hash) bool {
	if len(rangeRoots) != end-start {
		panic("VerifySectorRangeProof: number of sector roots does not match range")
	} else if start < 0 || end > numRoots || start > end || start == end {
		panic("VerifySectorRangeProof: illegal proof range")
	}
	if len(proof) != ProofSize(numRoots, start, end) {
		return false
	}

	var s Stack
	insertRange := func(i, j int) {
		for i < j {
			subtreeSize := nextSubtreeSize(i, j)
			height := bits.TrailingZeros(uint(subtreeSize)) // log2
			s.insertNodeHash(proof[0], height)
			proof = proof[1:]
			i += subtreeSize
		}
	}

	insertRange(0, start)
	for _, h := range rangeRoots {
		s.AppendLeafHash(h)
	}
	insertRange(end, numRoots)
	return s.Root() == root
}

// DiffProofSize returns the size of a diff proof for the specified actions.
func DiffProofSize(actions []renterhost.RPCWriteAction, numLeaves uint64) int {
	return 128
}

// BuildDiffProof constructs a diff proof for the specified actions.
func BuildDiffProof(actions []renterhost.RPCWriteAction, numLeaves uint64, sectorRoots []crypto.Hash) []crypto.Hash {
	return nil
}

// VerifyDiffProof verifies a proof produced by BuildDiffProof.
func VerifyDiffProof(actions []renterhost.RPCWriteAction, numLeaves uint64, proofHashes, leafHashes []crypto.Hash, oldRoot, newRoot crypto.Hash) bool {
	return true
}
