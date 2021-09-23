package merkle

import (
	"math/bits"
	"unsafe"

	"go.sia.tech/siad/crypto"
	"lukechampine.com/us/merkle/blake2b"
)

// "Stacks" are compressed Merkle trees; each element of the stack stores the
// root of a perfect subtree, and the index of the element indicates the size of
// the subtree. This makes it possible to perform various Merkle tree operations
// in log(n) space.
//
// Originally, there was just one stack type, which was used for both verifying
// proofs and computing roots. Later, I wrote optimized Merkle tree code that
// could hash multiple inputs simultaneously. While this greatly improved
// performance, it could not easily be integrated with the verification code,
// which generally deals with just one input at a time. So I split the
// implementation into two stacks: one for verifying proofs (proofStack) and one
// for computing roots as fast as possible (appendStack).

type proofStack struct {
	stack [17]crypto.Hash // ordered smallest-to-largest
	used  uint32          // one bit per stack elem
}

func (s *proofStack) hasNodeAtHeight(height int) bool {
	return s.used&(1<<height) != 0
}

func (s *proofStack) insertNode(h crypto.Hash, height int) {
	i := height
	for ; s.hasNodeAtHeight(i); i++ {
		h = blake2b.SumPair(s.stack[i], h)
	}
	s.stack[i] = h
	s.used += 1 << height
}

func (s *proofStack) root() crypto.Hash {
	i := bits.TrailingZeros32(s.used)
	if i == 32 {
		return crypto.Hash{}
	}
	root := s.stack[i]
	for i++; i < 32; i++ {
		if s.hasNodeAtHeight(i) {
			root = blake2b.SumPair(s.stack[i], root)
		}
	}
	return root
}

type appendStack struct {
	// Unlike proofStack, this stack is ordered largest-to-smallest, and stores
	// four subtree roots per height. This ordering allows us to cast two
	// adjacent stack elements into a single [8][32]byte, which reduces copying
	// when hashing.
	stack [15][4][32]byte
	// Since we operate on 8 nodes at a time, we need a buffer to hold nodes
	// until we have enough. And since the buffer is adjacent to the stack in
	// memory, we can again avoid some copying.
	nodeBuf [4][32]byte
	// Like proofStack, 'used' is both the number of leaves appended and a bit vector
	// that indicates which elements of the stack are active. We also use it to
	// determine how many nodes are the buffer.
	used uint32
}

// We rely on the nodeBuf field immediately following the last element of the
// stack field. This should always be true -- there's no reason for a compiler
// to insert padding between them -- but it doesn't hurt to check.
var _ [unsafe.Offsetof(appendStack{}.nodeBuf)]struct{} = [unsafe.Sizeof(appendStack{}.stack)]struct{}{}

func (s *appendStack) hasNodeAtHeight(i int) bool {
	// not as simple as in proofStack; order is reversed, and s.used is "off" by
	// a factor of 4
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
	// same as in proofStack, except that we operate on 8 nodes at a time,
	// exploiting the fact that the two groups of 4 are contiguous in memory
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
