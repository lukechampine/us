package merkle

import (
	"encoding/binary"
	"io"
	"math/bits"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"golang.org/x/crypto/blake2b"
)

// A Stack is a Merkle tree that stores only one (or zero) nodes per
// level. If a node is inserted at a level already containing a node, the
// nodes are merged into the next level. This process repeats until it reaches
// an open level.
//
// For example, after five nodes have been inserted, the stack only retains
// two nodes: one node created from the first four, and one node containing
// the last. After seven nodes have been inserted, the stack retains three
// nodes: one for the first four, one for the next two, and the last one.
//
// Stacks are an alternative to storing the full Merkle tree; they
// compress the tree to O(log2(n)) space at the cost of reduced functionality
// (nodes can only be appended to the "end" of the stack; arbitrary insertion
// is not possible). Stacks also distribute the number of hashing
// operations more evenly: instead of hashing the full tree all at once, the
// hashes are computed as needed at insertion time. (The total number of
// hashes performed is the same.)
type Stack struct {
	// NOTE: 64 hashes is enough to cover 2^64 * LeafSize bytes (1 ZiB), so
	// we don't need to worry about running out.
	stack [64]crypto.Hash
	used  uint64 // one bit per stack elem; also number of nodes
	buf   [1 + LeafSize]byte
}

// (*Stack).nodeHash assumes that LeafSize = crypto.HashSize * 2; verify this assumption at compile time
var _ [LeafSize]struct{} = [crypto.HashSize * 2]struct{}{}

func (s *Stack) leafHash(leaf []byte) crypto.Hash {
	if len(leaf) != LeafSize {
		panic("leafHash: illegal input size")
	}
	s.buf[0] = leafHashPrefix
	copy(s.buf[1:], leaf)
	return crypto.Hash(blake2b.Sum256(s.buf[:]))
}

func (s *Stack) nodeHash(left, right crypto.Hash) crypto.Hash {
	s.buf[0] = nodeHashPrefix
	copy(s.buf[1:], left[:])
	copy(s.buf[1+len(left):], right[:])
	return crypto.Hash(blake2b.Sum256(s.buf[:]))
}

// MarshalSia implements the encoding.SiaMarshaler interface.
func (s *Stack) MarshalSia(w io.Writer) error {
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
func (s *Stack) UnmarshalSia(r io.Reader) error {
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

// AppendLeafHash appends a leaf hash to the right side of the Merkle tree.
func (s *Stack) AppendLeafHash(h crypto.Hash) {
	// seek to first open slot, merging nodes as we go
	var i uint64
	for ; s.used&(1<<i) != 0; i++ {
		h = s.nodeHash(s.stack[i], h)
	}
	s.stack[i] = h
	s.used++ // nice
}

// NumLeaves returns the number of leaf hashes appended to the stack since the
// last call to Reset.
func (s *Stack) NumLeaves() int {
	return int(s.used)
}

// ReadFrom reads successive nodes from r, appending them to the stack.
func (s *Stack) ReadFrom(r io.Reader) (int64, error) {
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
		s.AppendLeafHash(node)
	}
}

// Reset clears the stack.
func (s *Stack) Reset() {
	s.used = 0 // nice
}

// Root returns the root of the Merkle tree. It does not modify the stack. If
// the stack is empty, Root returns a zero-valued hash.
func (s *Stack) Root() crypto.Hash {
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
