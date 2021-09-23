// Package merkle provides Sia-specific Merkle tree utilities.
package merkle // import "lukechampine.com/us/merkle"

import (
	"io"
	"math/bits"

	"go.sia.tech/siad/crypto"
	"lukechampine.com/us/merkle/blake2b"
	"lukechampine.com/us/renterhost"
)

const (
	// SegmentSize is the number of bytes in each leaf node of a sector's Merkle
	// tree. Although "LeafSize" would be a more accurate term, Sia refers to
	// leaves as "segments", so we will follow suit.
	SegmentSize = crypto.HashSize * 2

	// SegmentsPerSector is a convenience value.
	SegmentsPerSector = renterhost.SectorSize / SegmentSize
)

// Much of this code assumes that renterhost.SectorSize is a power of 2; verify
// this assumption at compile time.
var _ [0]struct{} = [renterhost.SectorSize & (renterhost.SectorSize - 1)]struct{}{}

// SectorRoot computes the Merkle root of a sector using SegmentSize bytes per
// leaf.
func SectorRoot(sector *[renterhost.SectorSize]byte) crypto.Hash {
	var s appendStack
	s.appendLeaves(sector[:])
	return s.root()
}

// MetaRoot calculates the root of a set of existing Merkle roots.
func MetaRoot(roots []crypto.Hash) crypto.Hash {
	// Stacks are only designed to store one sector's worth of leaves, so we'll
	// panic if we insert more than SegmentsPerSector nodes. To compensate, call
	// MetaRoot recursively.
	if len(roots) <= SegmentsPerSector {
		var s appendStack
		for _, r := range roots {
			s.appendNode(r)
		}
		return s.root()
	}
	// split at largest power of two
	split := 1 << (bits.Len(uint(len(roots)-1)) - 1)
	return blake2b.SumPair(MetaRoot(roots[:split]), MetaRoot(roots[split:]))
}

// ReaderRoot returns the Merkle root of the supplied stream, which must contain
// an integer multiple of segments.
func ReaderRoot(r io.Reader) (crypto.Hash, error) {
	var s appendStack
	leaves := make([]byte, SegmentSize*4)
	for {
		n, err := io.ReadFull(r, leaves)
		if err == io.EOF {
			break
		} else if err == io.ErrUnexpectedEOF && n%SegmentSize == 0 {
			// this is fine
		} else if err != nil {
			return crypto.Hash{}, err
		}
		s.appendLeaves(leaves[:n])
	}
	return s.root(), nil
}
