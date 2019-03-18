// Package merkle provides Sia-specific Merkle tree utilities.
package merkle // import "lukechampine.com/us/merkle"

import (
	"gitlab.com/NebulousLabs/Sia/crypto"
	"lukechampine.com/us/renterhost"
)

const (
	// SegmentSize is the number of bytes in each leaf node of a sector's Merkle
	// tree. Although "LeafSize" would be a more accurate term, Sia refers to
	// leaves as "segments", so we will follow suit.
	SegmentSize = crypto.HashSize * 2

	// SegmentsPerSector is a convenience value.
	SegmentsPerSector = renterhost.SectorSize / SegmentSize

	// prefixes used during hashing, as specified by RFC 6962
	leafHashPrefix = 0
	nodeHashPrefix = 1
)

// Much of this code assumes that renterhost.SectorSize is a power of 2; verify
// this assumption at compile time.
var _ [0]struct{} = [renterhost.SectorSize & (renterhost.SectorSize - 1)]struct{}{}

// SectorRoot computes the Merkle root of a sector using SegmentSize bytes per
// leaf.
func SectorRoot(sector *[renterhost.SectorSize]byte) crypto.Hash {
	var s stack
	for i := 0; i < len(sector); i += SegmentSize {
		s.appendLeaf(sector[i:][:SegmentSize])
	}
	return s.root()
}

// MetaRoot calculates the root of a set of existing Merkle roots.
func MetaRoot(roots []crypto.Hash) crypto.Hash {
	var s stack
	for _, r := range roots {
		s.insertNodeHash(r, 0)
	}
	return s.root()
}
