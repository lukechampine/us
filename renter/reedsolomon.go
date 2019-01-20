package renter

import (
	"bytes"
	"fmt"
	"io"

	"lukechampine.com/us/internal/reedsolomon"
	"lukechampine.com/us/merkle"
)

// An ErasureCoder encodes and decodes data to/from a set of shards. The
// encoding is done piecewise, such that every segment can be decoded
// individually.
type ErasureCoder interface {
	// Encode encodes data into shards. The resulting shards do not constitute
	// a single matrix, but a series of matrices, each with a shard size of
	// merkletree.Segmentsize. The supplied shards must each have a capacity
	// of at least len(data)/m.
	Encode(data []byte, shards [][]byte)
	// Reconstruct recalculates any missing shards in the input. Missing
	// shards must have the same capacity as a normal shard, but a length of
	// zero.
	Reconstruct(shards [][]byte) error
	// Recover recalculates any missing data shards and writes them to w,
	// stopping after n bytes.
	Recover(w io.Writer, shards [][]byte, n int) error
}

type rsCode struct {
	enc  *reedsolomon.ReedSolomon
	m, n int
}

func checkShards(shards [][]byte, n int) (shardSize int) {
	if len(shards) != n {
		panic(fmt.Sprintf("expected %v shards, got %v", n, len(shards)))
	}
	for i := range shards {
		if len(shards[i]) != 0 {
			if shardSize == 0 {
				shardSize = len(shards[i])
			} else if len(shards[i]) != shardSize {
				panic(reedsolomon.ErrShardSize)
			}
		}
	}
	if shardSize%merkle.SegmentSize != 0 {
		panic("shard size must be a multiple of SegmentSize")
	}
	return shardSize
}

func (rsc rsCode) Encode(data []byte, shards [][]byte) {
	chunkSize := rsc.m * merkle.SegmentSize
	numChunks := len(data) / chunkSize
	if len(data)%chunkSize != 0 {
		numChunks++
	}
	checkShards(shards, rsc.n)

	// extend shards to proper len
	shardSize := numChunks * merkle.SegmentSize
	for i := range shards {
		if cap(shards[i]) < shardSize {
			panic("each shard must have capacity of at least len(data)/m")
		}
		shards[i] = shards[i][:shardSize]
	}
	// treat shards as a sequence of segments. Iterate over each segment,
	// copying some data into the data shards, then calling Encode to fill the
	// parity shards.
	subshards := make([][]byte, 256)[:rsc.n]
	buf := bytes.NewBuffer(data)
	for off := 0; buf.Len() > 0; off += merkle.SegmentSize {
		for i := 0; i < rsc.m; i++ {
			copy(shards[i][off:], buf.Next(merkle.SegmentSize))
		}
		for i := range subshards {
			subshards[i] = shards[i][off:][:merkle.SegmentSize]
		}
		if err := rsc.enc.Encode(subshards); err != nil {
			panic(err)
		}
	}
}

func (rsc rsCode) Reconstruct(shards [][]byte) error {
	shardSize := checkShards(shards, rsc.n)

	subshards := make([][]byte, 256)[:rsc.n]
	for off := 0; off < shardSize; off += merkle.SegmentSize {
		for i := range shards {
			if len(shards[i]) == 0 {
				subshards[i] = shards[i][:shardSize][off:][:0]
			} else {
				subshards[i] = shards[i][off:][:merkle.SegmentSize]
			}
		}
		if err := rsc.enc.Reconstruct(subshards); err != nil {
			return err
		}
	}

	for i := range shards {
		shards[i] = shards[i][:shardSize]
	}
	return nil
}

func (rsc rsCode) Recover(w io.Writer, shards [][]byte, n int) error {
	checkShards(shards, rsc.n)

	subshards := make([][]byte, 256)[:rsc.n]
	rem := n
	for off := 0; rem > 0; off += merkle.SegmentSize {
		for i := range shards {
			if len(shards[i]) == 0 {
				subshards[i] = shards[i] // allow for use of extra capacity
			} else {
				subshards[i] = shards[i][off:][:merkle.SegmentSize]
			}
		}
		if err := rsc.enc.ReconstructData(subshards); err != nil {
			return err
		}
		writeLen := rsc.m * merkle.SegmentSize
		if writeLen > rem {
			writeLen = rem
		}
		if err := rsc.enc.Join(w, subshards, writeLen); err != nil {
			return err
		}
		rem -= writeLen
	}
	return nil
}

// NewRSCode returns an m-of-n ErasureCoder. It panics if m <= 0 or n < m.
func NewRSCode(m, n int) ErasureCoder {
	if m == n {
		return simpleRedundancy(m)
	}
	rsc, err := reedsolomon.New(m, n-m)
	if err != nil {
		panic(err)
	}
	return rsCode{
		enc: rsc,
		m:   m,
		n:   n,
	}
}

// simpleRedundancy implements the ErasureCoder interface when no
// parity shards are desired
type simpleRedundancy int

func (r simpleRedundancy) Encode(data []byte, shards [][]byte) {
	checkShards(shards, int(r))
	chunkSize := int(r) * merkle.SegmentSize
	numChunks := len(data) / chunkSize
	if len(data)%chunkSize != 0 {
		numChunks++
	}

	// extend shards to proper len
	shardSize := numChunks * merkle.SegmentSize
	for i := range shards {
		if cap(shards[i]) < shardSize {
			panic("each shard must have capacity of at least len(data)/m")
		}
		shards[i] = shards[i][:shardSize]
	}

	// treat shards as a sequence of segments. Iterate over each segment,
	// copying data into each shard.
	buf := bytes.NewBuffer(data)
	for off := 0; buf.Len() > 0; off += merkle.SegmentSize {
		for i := range shards {
			copy(shards[i][off:], buf.Next(merkle.SegmentSize))
		}
	}
}

func (r simpleRedundancy) Reconstruct(shards [][]byte) error {
	return r.checkShards(shards)
}

func (r simpleRedundancy) Recover(dst io.Writer, shards [][]byte, n int) error {
	if err := r.checkShards(shards); err != nil {
		return err
	}
	rem := n
	for off := 0; rem > 0; off += merkle.SegmentSize {
		for _, shard := range shards {
			s := shard[off:][:merkle.SegmentSize]
			if rem < len(s) {
				s = s[:rem]
			}
			n, err := dst.Write(s)
			if err != nil {
				return err
			}
			rem -= n
		}
	}
	return nil
}

func (r simpleRedundancy) checkShards(shards [][]byte) error {
	if len(shards) != int(r) {
		panic(fmt.Sprintf("expected %v shards, got %v", r, len(shards)))
	}
	for i := range shards {
		if len(shards[i]) == 0 {
			return reedsolomon.ErrTooFewShards
		} else if i > 0 && len(shards[i]) != len(shards[i-1]) {
			panic(reedsolomon.ErrShardSize)
		} else if len(shards[i])%merkle.SegmentSize != 0 {
			panic("shard size must be a multiple of SegmentSize")
		}
	}
	return nil
}
