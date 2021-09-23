package merkle

import (
	"io"
	"math"
	"math/bits"
	"sort"
	"unsafe"

	"go.sia.tech/siad/crypto"
	"lukechampine.com/us/merkle/blake2b"
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
	var s appendStack
	subtreeRoot := func(i, j int) crypto.Hash {
		s.reset()
		s.appendLeaves(sector[i*SegmentSize : j*SegmentSize])
		return s.root()
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
			return blake2b.SumPair(left, right)
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

	var s appendStack
	subtreeRoot := func(i, j int) crypto.Hash {
		s.reset()
		s.appendLeaves(segments[(i-start)*SegmentSize : (j-start)*SegmentSize])
		return s.root()
	}
	return verifyProof(proof, subtreeRoot, start, end, root)
}

// BuildSectorRangeProof constructs a proof for the sector range [start, end).
func BuildSectorRangeProof(sectorRoots []crypto.Hash, start, end int) []crypto.Hash {
	if len(sectorRoots) == 0 {
		return nil
	} else if start < 0 || end > len(sectorRoots) || start > end || start == end {
		panic("BuildSectorRangeProof: illegal proof range")
	}

	proof := make([]crypto.Hash, 0, ProofSize(len(sectorRoots), start, end))
	buildRange := func(i, j int) {
		for i < j && i < len(sectorRoots) {
			subtreeSize := nextSubtreeSize(i, j)
			if i+subtreeSize > len(sectorRoots) {
				subtreeSize = len(sectorRoots) - i
			}
			proof = append(proof, MetaRoot(sectorRoots[i:][:subtreeSize]))
			i += subtreeSize
		}
	}
	buildRange(0, start)
	buildRange(end, math.MaxInt32)
	return proof
}

// VerifySectorRangeProof verifies a proof produced by BuildSectorRangeProof.
func VerifySectorRangeProof(proof []crypto.Hash, rangeRoots []crypto.Hash, start, end, numRoots int, root crypto.Hash) bool {
	if numRoots == 0 {
		return len(proof) == 0
	} else if len(rangeRoots) != end-start {
		panic("VerifySectorRangeProof: number of sector roots does not match range")
	} else if start < 0 || end > numRoots || start > end || start == end {
		panic("VerifySectorRangeProof: illegal proof range")
	}
	if len(proof) != ProofSize(numRoots, start, end) {
		return false
	}

	var s proofStack
	insertRange := func(i, j int) {
		for i < j && len(proof) > 0 {
			subtreeSize := nextSubtreeSize(i, j)
			height := bits.TrailingZeros(uint(subtreeSize)) // log2
			s.insertNode(proof[0], height)
			proof = proof[1:]
			i += subtreeSize
		}
	}

	insertRange(0, start)
	for _, h := range rangeRoots {
		s.insertNode(h, 0)
	}
	insertRange(end, math.MaxInt32)
	return s.root() == root
}

// DiffProofSize returns the size of a diff proof for the specified actions.
func DiffProofSize(actions []renterhost.RPCWriteAction, numLeaves int) int {
	return 128
}

func sectorsChanged(actions []renterhost.RPCWriteAction, numSectors int) []int {
	newNumSectors := numSectors
	sectorsChanged := make(map[int]struct{})
	for _, action := range actions {
		switch action.Type {
		case renterhost.RPCWriteActionAppend:
			sectorsChanged[newNumSectors] = struct{}{}
			newNumSectors++

		case renterhost.RPCWriteActionTrim:
			for i := 0; i < int(action.A); i++ {
				newNumSectors--
				sectorsChanged[newNumSectors] = struct{}{}
			}

		case renterhost.RPCWriteActionSwap:
			sectorsChanged[int(action.A)] = struct{}{}
			sectorsChanged[int(action.B)] = struct{}{}

		default:
			panic("unknown or unsupported action type: " + action.Type.String())
		}
	}

	var sectorIndices []int
	for index := range sectorsChanged {
		if index < numSectors {
			sectorIndices = append(sectorIndices, index)
		}
	}
	sort.Ints(sectorIndices)
	return sectorIndices
}

// BuildDiffProof constructs a diff proof for the specified actions.
// ActionUpdate is not supported.
func BuildDiffProof(actions []renterhost.RPCWriteAction, sectorRoots []crypto.Hash) (treeHashes, leafHashes []crypto.Hash) {
	proofIndices := sectorsChanged(actions, len(sectorRoots))
	leafHashes = make([]crypto.Hash, len(proofIndices))
	for i, j := range proofIndices {
		leafHashes[i] = sectorRoots[j]
	}

	treeHashes = make([]crypto.Hash, 0, DiffProofSize(actions, len(sectorRoots)))
	buildRange := func(i, j int) {
		for i < j {
			subtreeSize := nextSubtreeSize(i, j)
			treeHashes = append(treeHashes, MetaRoot(sectorRoots[i:][:subtreeSize]))
			i += subtreeSize
		}
	}

	start := 0
	for _, end := range proofIndices {
		buildRange(start, end)
		start = end + 1
	}
	buildRange(start, len(sectorRoots))

	return
}

func unsafeSectorRoot(sector []byte) crypto.Hash {
	if len(sector) != renterhost.SectorSize {
		panic("invalid sector length")
	}
	return SectorRoot((*[renterhost.SectorSize]byte)(unsafe.Pointer(&sector[0])))
}

// PrecomputeAppendRoots computes the SectorRoots of any Append actions in the
// provided slice.
func PrecomputeAppendRoots(actions []renterhost.RPCWriteAction) []crypto.Hash {
	roots := make([]crypto.Hash, 0, len(actions))
	for _, action := range actions {
		if action.Type == renterhost.RPCWriteActionAppend {
			roots = append(roots, unsafeSectorRoot(action.Data))
		}
	}
	return roots
}

// VerifyDiffProof verifies a proof produced by BuildDiffProof. ActionUpdate is
// not supported. If appendRoots is non-nil, it is assumed to contain the
// precomputed SectorRoots of all Append actions.
func VerifyDiffProof(actions []renterhost.RPCWriteAction, numLeaves int, treeHashes, leafHashes []crypto.Hash, oldRoot, newRoot crypto.Hash, appendRoots []crypto.Hash) bool {
	verifyMulti := func(proofIndices []int, treeHashes, leafHashes []crypto.Hash, numLeaves int, root crypto.Hash) bool {
		var s proofStack
		insertRange := func(i, j int) {
			for i < j {
				subtreeSize := nextSubtreeSize(i, j)
				height := bits.TrailingZeros(uint(subtreeSize)) // log2
				s.insertNode(treeHashes[0], height)
				treeHashes = treeHashes[1:]
				i += subtreeSize
			}
		}

		start := 0
		for i, end := range proofIndices {
			insertRange(start, end)
			start = end + 1
			s.insertNode(leafHashes[i], 0)
		}
		insertRange(start, numLeaves)

		return s.root() == root
	}

	// first use the original proof to construct oldRoot
	proofIndices := sectorsChanged(actions, numLeaves)
	if len(proofIndices) != len(leafHashes) {
		return false
	}
	if !verifyMulti(proofIndices, treeHashes, leafHashes, numLeaves, oldRoot) {
		return false
	}

	// then modify the proof according to actions and construct the newRoot
	newLeafHashes := modifyLeaves(leafHashes, actions, numLeaves, appendRoots)
	newProofIndices := modifyProofRanges(proofIndices, actions, numLeaves)
	numLeaves += len(newLeafHashes) - len(leafHashes)

	return verifyMulti(newProofIndices, treeHashes, newLeafHashes, numLeaves, newRoot)
}

// modifyProofRanges modifies the proof ranges produced by calculateProofRanges
// to verify a post-modification Merkle diff proof for the specified actions.
func modifyProofRanges(proofIndices []int, actions []renterhost.RPCWriteAction, numSectors int) []int {
	for _, action := range actions {
		switch action.Type {
		case renterhost.RPCWriteActionAppend:
			proofIndices = append(proofIndices, numSectors)
			numSectors++

		case renterhost.RPCWriteActionTrim:
			proofIndices = proofIndices[:len(proofIndices)-int(action.A)]
			numSectors -= int(action.A)

		case renterhost.RPCWriteActionSwap:
		case renterhost.RPCWriteActionUpdate:

		default:
			panic("unknown or unsupported action type: " + action.Type.String())
		}
	}
	return proofIndices
}

// modifyLeaves modifies the leaf hashes of a Merkle diff proof to verify a
// post-modification Merkle diff proof for the specified actions.
func modifyLeaves(leafHashes []crypto.Hash, actions []renterhost.RPCWriteAction, numSectors int, appendRoots []crypto.Hash) []crypto.Hash {
	// determine which sector index corresponds to each leaf hash
	var indices []int
	for _, action := range actions {
		switch action.Type {
		case renterhost.RPCWriteActionAppend:
			indices = append(indices, numSectors)
			numSectors++
		case renterhost.RPCWriteActionTrim:
			for j := uint64(0); j < action.A; j++ {
				numSectors--
				indices = append(indices, numSectors)
			}
		case renterhost.RPCWriteActionSwap:
			indices = append(indices, int(action.A), int(action.B))

		default:
			panic("unknown or unsupported action type: " + action.Type.String())
		}
	}
	sort.Ints(indices)
	indexMap := make(map[int]int, len(leafHashes))
	for i, index := range indices {
		if i > 0 && index == indices[i-1] {
			continue // remove duplicates
		}
		indexMap[index] = len(indexMap)
	}
	leafHashes = append([]crypto.Hash(nil), leafHashes...)
	for _, action := range actions {
		switch action.Type {
		case renterhost.RPCWriteActionAppend:
			var root crypto.Hash
			if len(appendRoots) > 0 {
				root, appendRoots = appendRoots[0], appendRoots[1:]
			} else {
				root = unsafeSectorRoot(action.Data)
			}
			leafHashes = append(leafHashes, root)

		case renterhost.RPCWriteActionTrim:
			leafHashes = leafHashes[:len(leafHashes)-int(action.A)]

		case renterhost.RPCWriteActionSwap:
			i, j := indexMap[int(action.A)], indexMap[int(action.B)]
			leafHashes[i], leafHashes[j] = leafHashes[j], leafHashes[i]

		default:
			panic("unknown or unsupported action type: " + action.Type.String())
		}
	}
	return leafHashes
}

// A RangeProofVerifier allows for proofs to be verified in streaming fashion.
type RangeProofVerifier struct {
	start, end int
	roots      []crypto.Hash
}

// ReadFrom implements io.ReaderFrom.
func (rpv *RangeProofVerifier) ReadFrom(r io.Reader) (int64, error) {
	var total int64
	i, j := rpv.start, rpv.end
	for i < j {
		subtreeSize := nextSubtreeSize(i, j)
		n := int64(subtreeSize * SegmentSize)
		root, err := ReaderRoot(io.LimitReader(r, n))
		if err != nil {
			return total, err
		}
		total += n
		rpv.roots = append(rpv.roots, root)
		i += subtreeSize
	}
	return total, nil
}

// Verify verifies the supplied proof, using the data ingested from ReadFrom.
func (rpv *RangeProofVerifier) Verify(proof []crypto.Hash, root crypto.Hash) bool {
	if len(proof) != ProofSize(SegmentsPerSector, rpv.start, rpv.end) {
		return false
	}
	var s proofStack
	consume := func(roots *[]crypto.Hash, i, j int) {
		for i < j && len(*roots) > 0 {
			subtreeSize := nextSubtreeSize(i, j)
			height := bits.TrailingZeros(uint(subtreeSize)) // log2
			s.insertNode((*roots)[0], height)
			*roots = (*roots)[1:]
			i += subtreeSize
		}
	}
	consume(&proof, 0, rpv.start)
	consume(&rpv.roots, rpv.start, rpv.end)
	consume(&proof, rpv.end, SegmentsPerSector)
	return s.root() == root
}

// NewRangeProofVerifier returns a RangeProofVerifier for the sector range
// [start, end).
func NewRangeProofVerifier(start, end int) *RangeProofVerifier {
	return &RangeProofVerifier{
		start: start,
		end:   end,
	}
}

// ConvertProofOrdering converts "left-to-right" proofs into the "leaf-to-root"
// ordering used in consensus storage proofs.
func ConvertProofOrdering(proof []crypto.Hash, index int) []crypto.Hash {
	// strategy: split proof into lefts and rights, then iterate over bits in
	// leaf-to-root order, selecting either a left or right hash as appropriate.
	lefts := proof[:bits.OnesCount(uint(index))]
	rights := proof[len(lefts):]
	reordered := make([]crypto.Hash, 0, len(proof))
	for i := 0; len(reordered) < len(proof); i++ {
		if index&(1<<i) != 0 {
			reordered = append(reordered, lefts[len(lefts)-1])
			lefts = lefts[:len(lefts)-1]
		} else if len(rights) > 0 {
			reordered = append(reordered, rights[0])
			rights = rights[1:]
		}
	}
	return reordered
}
