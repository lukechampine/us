// Package merkle provides Sia-specific Merkle tree utilities.
package merkle

import (
	"gitlab.com/NebulousLabs/Sia/crypto"
	"golang.org/x/crypto/blake2b"
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

// hashBuffer is a helper type for calculating hashes within a Merkle tree.
type hashBuffer [1 + SegmentSize]byte

func (buf *hashBuffer) leafHash(segment []byte) crypto.Hash {
	if len(segment) != SegmentSize {
		panic("leafHash: illegal input size")
	}
	buf[0] = leafHashPrefix
	copy(buf[1:], segment)
	return crypto.Hash(blake2b.Sum256(buf[:]))
}

func (buf *hashBuffer) nodeHash(left, right crypto.Hash) crypto.Hash {
	buf[0] = nodeHashPrefix
	copy(buf[1:], left[:])
	copy(buf[1+len(left):], right[:])
	return crypto.Hash(blake2b.Sum256(buf[:]))
}

// SectorRoot computes the Merkle root of a sector, using the standard Sia
// leaf size.
func SectorRoot(sector *[renterhost.SectorSize]byte) crypto.Hash {
	var s Stack
	for i := 0; i < len(sector); i += SegmentSize {
		s.AppendNode(s.leafHash(sector[i:][:SegmentSize]))
	}
	return s.Root()
}

// CachedRoot calculates the root of a set of existing Merkle roots.
func CachedRoot(roots []crypto.Hash) crypto.Hash {
	var s Stack
	for _, r := range roots {
		s.AppendNode(r)
	}
	return s.Root()
}
