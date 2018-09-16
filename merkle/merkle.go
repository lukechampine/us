// Package merkle provides Sia-specific Merkle tree utilities.
package merkle

import (
	"gitlab.com/NebulousLabs/Sia/crypto"
	"lukechampine.com/us/renterhost"
)

const (
	// SegmentSize is the number of bytes in each leaf node of a sector's Merkle
	// tree.
	SegmentSize = crypto.HashSize * 2

	// SegmentsPerSector is a convenience value.
	SegmentsPerSector = renterhost.SectorSize / SegmentSize

	// prefixes used during hashing, as specified by RFC 6962
	leafHashPrefix = 0
	nodeHashPrefix = 1
)

// Much of this code assumes that renterhost.SectorSize is a power of 2; verify this assumption at compile time
var _ [0]struct{} = [renterhost.SectorSize & (renterhost.SectorSize - 1)]struct{}{}

// SectorRoot computes the Merkle root of a sector, using the standard Sia
// leaf size.
func SectorRoot(sector *[renterhost.SectorSize]byte) crypto.Hash {
	var s Stack
	for i := 0; i < len(sector); i += SegmentSize {
		s.AppendNode(s.leafHash(sector[i:][:SegmentSize]))
	}
	return s.Root()
}

// MetaRoot calculates the root of a set of existing Merkle roots.
func MetaRoot(roots []crypto.Hash) crypto.Hash {
	var s Stack
	for _, r := range roots {
		s.AppendNode(r)
	}
	return s.Root()
}
