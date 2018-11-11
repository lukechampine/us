package merkle

import (
	"math/bits"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"lukechampine.com/us/renterhost"
)

func proofSize(start, end int) int {
	// NOTE: I realize this is a bit magical (in a bad way), but it's too
	// pretty for me not to use it. If you have some spare time, try to figure
	// out why it works!
	zerosCount := func(x uint) int { return bits.OnesCount(^x) - (bits.LeadingZeros(SegmentsPerSector) + 1) }
	return bits.OnesCount(uint(start)) + zerosCount(uint(end-1))
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
			s.AppendLeafHash(s.leafHash(sector[i*LeafSize:][:LeafSize]))
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
	proof := make([]crypto.Hash, 0, proofSize(start, end))
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

// verifyProof verifies a proof produced by BuildProof. This is a generic
// version, used by VerifyProof and VerifyProofWithRoots.
func verifyProof(proof []crypto.Hash, subtreeRoot func(i, j int) crypto.Hash, start, end int, root crypto.Hash) bool {
	if len(proof) != proofSize(start, end) {
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
	if len(segments)%LeafSize != 0 {
		panic("VerifyProof: segments must be a multiple of LeafSize")
	} else if len(segments) != (end-start)*LeafSize {
		panic("VerifyProof: segments length does not match range")
	} else if start < 0 || end > SegmentsPerSector || start > end || start == end {
		panic("VerifyProof: illegal proof range")
	}

	var s Stack
	subtreeRoot := func(i, j int) crypto.Hash {
		s.Reset()
		for ; i < j; i++ {
			s.AppendLeafHash(s.leafHash(segments[(i-start)*LeafSize:][:LeafSize]))
		}
		return s.Root()
	}
	return verifyProof(proof, subtreeRoot, start, end, root)
}

// VerifyProofWithRoots verifies a proof produced by BuildProof using segment
// roots instead of segment data.
func VerifyProofWithRoots(proof []crypto.Hash, segmentRoots []crypto.Hash, start, end int, root crypto.Hash) bool {
	if len(segmentRoots) != end-start {
		panic("VerifyProofWithRoots: number of segment roots does not match range")
	} else if start < 0 || end > SegmentsPerSector || start > end || start == end {
		panic("VerifyProofWithRoots: illegal proof range")
	}

	// define a helper function for later
	var s Stack
	subtreeRoot := func(i, j int) crypto.Hash {
		s.Reset()
		for ; i < j; i++ {
			s.AppendLeafHash(segmentRoots[i-start])
		}
		return s.Root()
	}
	return verifyProof(proof, subtreeRoot, start, end, root)
}
