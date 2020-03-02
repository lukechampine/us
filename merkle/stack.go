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

type appendStack struct {
	stack   [15][4][32]byte
	nodeBuf [4][32]byte
	used    uint32
}

// We rely on the nodeBuf field immediately following the last element of the
// stack field. This should always be true -- there's no reason for a compiler
// to insert padding between them -- but it doesn't hurt to check.
var _ [unsafe.Offsetof(appendStack{}.nodeBuf)]struct{} = [unsafe.Sizeof(appendStack{}.stack)]struct{}{}

func (s *appendStack) hasNodeAtHeight(i int) bool {
	return (s.used>>2)&(1<<(len(s.stack)-i-1)) != 0
}

func (s *appendStack) reset() {
	s.used = 0 // nice
}

func (s *appendStack) appendNode(h [32]byte) {
	s.nodeBuf[s.used%4] = h
	s.used++
	if s.used%4 == 0 {
		s.used -= 4 // offset mergeNodeBuf adding 4
		s.mergeNodeBuf()
	}
}

func (s *appendStack) appendLeaves(leaves []byte) {
	if len(leaves)%SegmentSize != 0 {
		panic("appendLeaves: illegal input size")
	}
	rem := len(leaves) % (SegmentSize * 4)
	for i := 0; i < len(leaves)-rem; i += SegmentSize * 4 {
		blake2b.SumLeaves(&s.nodeBuf, (*[4][64]byte)(unsafe.Pointer(&leaves[i])))
		s.mergeNodeBuf()
	}
	for i := len(leaves) - rem; i < len(leaves); i += SegmentSize {
		s.appendNode(blake2b.SumLeaf((*[64]byte)(unsafe.Pointer(&leaves[i]))))
	}
}

func (s *appendStack) mergeNodeBuf() {
	nodes := &s.nodeBuf
	i := len(s.stack) - 1
	for ; s.hasNodeAtHeight(i); i-- {
		blake2b.SumNodes(&s.stack[i], (*[8][32]byte)(unsafe.Pointer(&s.stack[i])))
		nodes = &s.stack[i]
	}
	s.stack[i] = *nodes
	s.used += 4
}

func (s *appendStack) root() [32]byte {
	if s.used == 0 {
		return [32]byte{}
	}

	// helper function for computing the root of a stack element
	root4 := func(nodes [4][32]byte) [32]byte {
		// NOTE: it would be more efficient to point to the stack elements
		// directly, but that would make root non-idempotent
		in := (*[8][32]byte)(unsafe.Pointer(&[2][4][32]byte{0: nodes}))
		out := (*[4][32]byte)(unsafe.Pointer(in))
		blake2b.SumNodes(out, in)
		blake2b.SumNodes(out, in)
		return out[0]
	}

	i := len(s.stack) - 1 - bits.TrailingZeros32(s.used>>2)
	var root [32]byte
	switch s.used % 4 {
	case 0:
		root = root4(s.stack[i])
		i--
	case 1:
		root = s.nodeBuf[0]
	case 2:
		root = blake2b.SumPair(s.nodeBuf[0], s.nodeBuf[1])
	case 3:
		root = blake2b.SumPair(blake2b.SumPair(s.nodeBuf[0], s.nodeBuf[1]), s.nodeBuf[2])
	}
	for ; i >= 0; i-- {
		if s.hasNodeAtHeight(i) {
			root = blake2b.SumPair(root4(s.stack[i]), root)
		}
	}
	return root
}
