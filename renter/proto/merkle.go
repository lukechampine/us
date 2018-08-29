package proto

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/bits"
	"sync"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"golang.org/x/crypto/blake2b"
)

const (
	// SegmentSize is the number of bytes in each leaf node of a sector's Merkle
	// tree.
	SegmentSize = 64

	// SegmentsPerSector is a convenience value.
	SegmentsPerSector = SectorSize / SegmentSize

	// prefixes used during hashing, as specified by RFC 6962
	leafHashPrefix = 0
	nodeHashPrefix = 1
)

// Much of this code assumes that SectorSize is a power of 2; verify this assumption at compile time
var _ [0]struct{} = [SectorSize & (SectorSize - 1)]struct{}{}

// SectorMerkleRoot computes the Merkle root of a sector, using the standard
// Sia leaf size.
func SectorMerkleRoot(sector *[SectorSize]byte) crypto.Hash {
	// maximize parallelism by calculating each subtree on its own CPU.
	// 8 seems like a reasonable default.
	const numSubtrees = 8
	subtrees := make([]crypto.Hash, numSubtrees)
	const rootsPerSubtree = SegmentsPerSector / numSubtrees
	var wg sync.WaitGroup
	wg.Add(numSubtrees)
	for i := range subtrees {
		go func(i int) {
			sectorData := bytes.NewBuffer(sector[i*rootsPerSubtree*SegmentSize:])
			// instead of calculating the full set of segment roots and then
			// merging them all, break the work into smaller pieces. Not only
			// does this reduce total memory footprint, it also prevents a
			// heap allocation, because the full set of segment roots is too
			// large to fit on the stack. 256 seems to be the sweet spot.
			const numSubsubtrees = 256
			subsubtrees := make([]crypto.Hash, numSubsubtrees)
			roots := make([]crypto.Hash, rootsPerSubtree/numSubsubtrees)
			buf := make([]byte, 1+SegmentSize)
			buf[0] = leafHashPrefix
			for j := range subsubtrees {
				for k := range roots {
					copy(buf[1:], sectorData.Next(SegmentSize))
					roots[k] = crypto.Hash(blake2b.Sum256(buf))
				}
				subsubtrees[j] = cachedMerkleRootAlias(roots)
			}
			subtrees[i] = cachedMerkleRootAlias(subsubtrees)
			wg.Done()
		}(i)
	}
	wg.Wait()
	return cachedMerkleRootAlias(subtrees)
}

// CachedMerkleRoot calculates the root of a set of existing Merkle roots.
func CachedMerkleRoot(roots []crypto.Hash) crypto.Hash {
	return cachedMerkleRootAlias(append([]crypto.Hash(nil), roots...))
}

// cachedMerkleRootAlias calculates the root of a set of existing Merkle
// roots, using the memory of roots as scratch space.
func cachedMerkleRootAlias(roots []crypto.Hash) crypto.Hash {
	if len(roots) == 0 {
		return crypto.Hash{}
	}

	buf := make([]byte, 1+crypto.HashSize*2)
	buf[0] = nodeHashPrefix
	newRoots := roots
	for len(roots) > 1 {
		newRoots = newRoots[:0]
		for i := 0; i < len(roots); i += 2 {
			if i+1 >= len(roots) {
				newRoots = append(newRoots, roots[i])
				break
			}
			copy(buf[1:], roots[i][:])
			copy(buf[1+crypto.HashSize:], roots[i+1][:])
			newRoots = append(newRoots, crypto.Hash(blake2b.Sum256(buf)))
		}
		roots = newRoots
	}
	return roots[0]
}

// A MerkleStack is a Merkle tree that stores only one (or zero) nodes per
// level. If a node is inserted at a level already containing a node, the
// nodes are merged into the next level. This process repeats until it reaches
// an open level.
//
// For example, after five nodes have been inserted, the stack only retains
// two nodes: one node created from the first four, and one node containing
// the last. After seven nodes have been inserted, the stack retains three
// nodes: one for the first four, one for the next two, and the last one.
//
// MerkleStacks are an alternative to storing the full Merkle tree; they
// compress the tree to O(log2(n)) space at the cost of reduced functionality
// (nodes can only be appended to the "end" of the stack; arbitrary insertion
// is not possible). MerkleStacks also distribute the number of hashing
// operations more evenly: instead of hashing the full tree all at once, the
// hashes are computed as needed at insertion time. (The total number of
// hashes performed is the same.)
type MerkleStack struct {
	// NOTE: 64 hashes is enough to cover 2^64 * SegmentSize bytes (1 ZiB), so
	// we don't need to worry about running out.
	stack [64]crypto.Hash
	used  uint64   // one bit per stack elem; also number of nodes
	buf   [65]byte // for hashing leaves and nodes
}

// MarshalSia implements the encoding.SiaMarshaler interface.
func (s *MerkleStack) MarshalSia(w io.Writer) error {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, s.used)
	_, err := w.Write(buf)
	if err != nil {
		return err
	}
	for _, h := range s.stack[:bits.Len64(s.used)] {
		if _, err := w.Write(h[:]); err != nil {
			return err
		}
	}
	return nil
}

// UnmarshalSia implements the encoding.SiaUnmarshaler interface.
func (s *MerkleStack) UnmarshalSia(r io.Reader) error {
	buf := make([]byte, 8)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return err
	}
	s.used = binary.LittleEndian.Uint64(buf)
	for i := range s.stack[:bits.Len64(s.used)] {
		if _, err := io.ReadFull(r, s.stack[i][:]); err != nil {
			return err
		}
	}
	return nil
}

func (s *MerkleStack) leafHash(segment []byte) crypto.Hash {
	if len(segment) != SegmentSize {
		panic("leafHash: illegal input size")
	}
	s.buf[0] = leafHashPrefix
	copy(s.buf[1:], segment)
	return crypto.Hash(blake2b.Sum256(s.buf[:]))
}

func (s *MerkleStack) nodeHash(left, right crypto.Hash) crypto.Hash {
	s.buf[0] = nodeHashPrefix
	copy(s.buf[1:], left[:])
	copy(s.buf[1+len(left):], right[:])
	return crypto.Hash(blake2b.Sum256(s.buf[:]))
}

// AppendNode appends node to the right side of the Merkle tree.
func (s *MerkleStack) AppendNode(node crypto.Hash) {
	// seek to first open slot, merging nodes as we go
	var i uint64
	for ; s.used&(1<<i) != 0; i++ {
		node = s.nodeHash(s.stack[i], node)
	}
	s.stack[i] = node
	s.used++ // nice
}

// NumNodes returns the number of nodes appended to the stack since the last
// call to Reset.
func (s *MerkleStack) NumNodes() int {
	return int(s.used)
}

// ReadFrom reads successive nodes from r, appending them to the stack.
func (s *MerkleStack) ReadFrom(r io.Reader) (int64, error) {
	var total int64
	for {
		var node crypto.Hash
		n, err := io.ReadFull(r, node[:])
		total += int64(n)
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return total, err
		}
		s.AppendNode(node)
	}
}

// Reset clears the stack.
func (s *MerkleStack) Reset() {
	s.used = 0 // nice
}

// Root returns the root of the Merkle tree. It does not modify the stack. If
// the stack is empty, Root returns a zero-valued hash.
func (s *MerkleStack) Root() crypto.Hash {
	i := uint64(bits.TrailingZeros64(s.used))
	if i == 64 {
		return crypto.Hash{}
	}
	root := s.stack[i]
	for i++; i < 64; i++ {
		if s.used&(1<<i) != 0 {
			root = s.nodeHash(s.stack[i], root)
		}
	}
	return root
}

func proofSize(start, end int) int {
	// NOTE: I realize this is a bit magical (in a bad way), but it's too
	// pretty for me not to use it. If you have some spare time, try to figure
	// out why it works!
	zerosCount := func(x uint) int { return bits.OnesCount(^x) - (bits.LeadingZeros(SegmentsPerSector) + 1) }
	return bits.OnesCount(uint(start)) + zerosCount(uint(end-1))
}

// BuildMerkleProof constructs a proof for the segment range [start, end). If
// a non-nil precalc function is provided, it will be used to supply
// precalculated subtree Merkle roots. For example, if the root of the left
// half of the Merkle tree is precomputed, precalc should return it for i == 0
// and j == SegmentsPerSector/2. If a precalculated root is not available,
// precalc should return the zero hash.
func BuildMerkleProof(sector *[SectorSize]byte, start, end int, precalc func(i, j int) crypto.Hash) []crypto.Hash {
	if start < 0 || end > SegmentsPerSector || start > end || start == end {
		panic("BuildMerkleProof: illegal proof range")
	}
	if precalc == nil {
		precalc = func(i, j int) (h crypto.Hash) { return }
	}

	// define a helper function for later
	var s MerkleStack
	subtreeRoot := func(i, j int) crypto.Hash {
		s.Reset()
		for ; i < j; i++ {
			s.AppendNode(s.leafHash(sector[i*SegmentSize:][:SegmentSize]))
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

// VerifyMerkleProof verifies a proof produced by BuildMerkleProof. Only
// sector-sized proofs can be verified.
func VerifyMerkleProof(proof []crypto.Hash, segments []byte, start, end int, root crypto.Hash) bool {
	if len(segments)%SegmentSize != 0 {
		panic("VerifyMerkleProof: segments must be a multiple of SegmentSize")
	} else if len(segments) != (end-start)*SegmentSize {
		panic("VerifyMerkleProof: segments length does not match range")
	} else if start < 0 || end > SegmentsPerSector || start > end || start == end {
		panic("VerifyMerkleProof: illegal proof range")
	}

	if len(proof) != proofSize(start, end) {
		return false
	}

	// define a helper function for later
	var s MerkleStack
	subtreeRoot := func(i, j int) crypto.Hash {
		s.Reset()
		for ; i < j; i++ {
			s.AppendNode(s.leafHash(segments[(i-start)*SegmentSize:][:SegmentSize]))
		}
		return s.Root()
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
			return s.nodeHash(left, right)
		}
	}
	return rec(0, SegmentsPerSector) == root
}
