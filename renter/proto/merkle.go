package proto

import (
	"bytes"
	"sync"

	"github.com/NebulousLabs/Sia/crypto"
	"golang.org/x/crypto/blake2b"
)

const (
	// SegmentSize is the number of bytes in each leaf node of a sector's Merkle
	// tree.
	SegmentSize = 64

	// SegmentsPerSector is a convenience value.
	SegmentsPerSector = SectorSize / SegmentSize

	// prefixes used during hashing, as specified by RFC 6962
	leafHashPrefix = 0
	nodeHashPrefix = 1
)

// SectorMerkleRoot computes the Merkle root of a sector, using the standard
// Sia leaf size.
func SectorMerkleRoot(sector *[SectorSize]byte) crypto.Hash {
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
				subsubtrees[j] = cachedMerkleRootAlias(roots)
			}
			subtrees[i] = cachedMerkleRootAlias(subsubtrees)
			wg.Done()
		}(i)
	}
	wg.Wait()
	return cachedMerkleRootAlias(subtrees)
}

// CachedMerkleRoot calculates the root of a set of existing Merkle roots.
func CachedMerkleRoot(roots []crypto.Hash) crypto.Hash {
	return cachedMerkleRootAlias(append([]crypto.Hash(nil), roots...))
}

// cachedMerkleRootAlias calculates the root of a set of existing Merkle
// roots, using the memory of roots as scratch space.
func cachedMerkleRootAlias(roots []crypto.Hash) crypto.Hash {
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
