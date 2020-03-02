package merkle

import (
	"math/bits"
	"unsafe"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"lukechampine.com/us/merkle/blake2b"
)

// A stack is a Merkle tree that stores only one (or zero) nodes per level. If a
// node is inserted at a level already containing a node, the nodes are merged
// into the next level. This process repeats until it reaches an open level.
//
// Stacks are an alternative to storing the full Merkle tree; they compress the
// tree to O(log2(n)) space at the cost of reduced functionality (nodes can only
// be appended to the "end" of the stack; arbitrary insertion is not possible).
//
// This implementation only supports trees with up to SegmentsPerSector leaves.
type stack struct {
	stack [17]crypto.Hash
	used  uint32 // one bit per stack elem; also number of nodes
}

func (s *stack) nodeHash(left, right crypto.Hash) crypto.Hash {
	return blake2b.SumPair(left, right)
}

// insertNodeHash inserts a node hash into the stack at the specified height. If
// a hash is already present at that height, the hashes are merged up the tree
// until an empty slot is reached.
func (s *stack) insertNodeHash(h crypto.Hash, height int) {
	// seek to first open slot, merging nodes as we go
	i := uint64(height)
	for ; s.used&(1<<i) != 0; i++ {
		h = s.nodeHash(s.stack[i], h)
	}
	s.stack[i] = h
	s.used += 1 << uint(height) // nice
}

// appendLeaf inserts the hash of leaf at height 0.
func (s *stack) appendLeaf(leaf []byte) {
	if len(leaf) != SegmentSize {
		panic("leafHash: illegal input size")
	}
	s.insertNodeHash(blake2b.SumLeaf((*[64]byte)(unsafe.Pointer(&leaf[0]))), 0)
}

// reset clears the stack.
func (s *stack) reset() {
	s.used = 0 // nice
}

// root returns the root of the Merkle tree. It does not modify the stack. If
// the stack is empty, root returns a zero-valued hash.
func (s *stack) root() crypto.Hash {
	i := bits.TrailingZeros32(s.used)
	if i == 32 {
		return crypto.Hash{}
	}
	root := s.stack[i]
	for i++; i < 32; i++ {
		if s.used&(1<<i) != 0 {
			root = s.nodeHash(s.stack[i], root)
		}
	}
	return root
}
