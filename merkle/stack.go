package merkle

import (
	"math/bits"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"golang.org/x/crypto/blake2b"
)

// A Stack is a Merkle tree that stores only one (or zero) nodes per
// level. If a node is inserted at a level already containing a node, the
// nodes are merged into the next level. This process repeats until it reaches
// an open level.
//
// Stacks are an alternative to storing the full Merkle tree; they
// compress the tree to O(log2(n)) space at the cost of reduced functionality
// (nodes can only be appended to the "end" of the stack; arbitrary insertion
// is not possible).
type stack struct {
	// NOTE: 64 hashes is enough to cover 2^64 * SegmentSize bytes (1 ZiB), so
	// we don't need to worry about running out.
	stack [64]crypto.Hash
	used  uint64 // one bit per stack elem; also number of nodes
	buf   [1 + SegmentSize]byte
}

// (*stack).nodeHash assumes that SegmentSize = crypto.HashSize * 2; verify this
// assumption at compile time
var _ [SegmentSize]struct{} = [crypto.HashSize * 2]struct{}{}

func (s *stack) nodeHash(left, right crypto.Hash) crypto.Hash {
	s.buf[0] = nodeHashPrefix
	copy(s.buf[1:], left[:])
	copy(s.buf[1+len(left):], right[:])
	return crypto.Hash(blake2b.Sum256(s.buf[:]))
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
	s.buf[0] = leafHashPrefix
	copy(s.buf[1:], leaf)
	h := crypto.Hash(blake2b.Sum256(s.buf[:]))
	s.insertNodeHash(h, 0)
}

// reset clears the stack.
func (s *stack) reset() {
	s.used = 0 // nice
}

// root returns the root of the Merkle tree. It does not modify the stack. If
// the stack is empty, root returns a zero-valued hash.
func (s *stack) root() crypto.Hash {
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
