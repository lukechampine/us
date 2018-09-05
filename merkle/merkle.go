// Package merkle provides Sia-specific Merkle tree utilities.
package merkle

import (
	"bytes"
	"sync"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"golang.org/x/crypto/blake2b"
	"lukechampine.com/us/renterhost"
)

const (
	// SegmentSize is the number of bytes in each leaf node of a sector's Merkle
	// tree.
	SegmentSize = 64

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
				subsubtrees[j] = cachedRootAlias(roots)
			}
			subtrees[i] = cachedRootAlias(subsubtrees)
			wg.Done()
		}(i)
	}
	wg.Wait()
	return cachedRootAlias(subtrees)
}

// CachedRoot calculates the root of a set of existing Merkle roots.
func CachedRoot(roots []crypto.Hash) crypto.Hash {
	return cachedRootAlias(append([]crypto.Hash(nil), roots...))
}

// cachedRootAlias calculates the root of a set of existing Merkle
// roots, using the memory of roots as scratch space.
func cachedRootAlias(roots []crypto.Hash) crypto.Hash {
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
