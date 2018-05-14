package renter

import (
	"bytes"
	"io"

	"github.com/klauspost/reedsolomon"
)

// An ErasureCoder encodes and decodes data to/from a set of shards.
type ErasureCoder interface {
	Encode(data []byte) [][]byte
	Reconstruct(shards [][]byte) error
	Recover(w io.Writer, shards [][]byte, writeLen int) error
}

// NewRSCode returns an m-of-n ErasureCoder. It panics if m <= 0 or n < m.
func NewRSCode(m, n int) ErasureCoder {
	if n == m {
		return simpleRedundancy(m)
	}
	rsc, err := reedsolomon.New(m, n-m)
	if err != nil {
		panic(err)
	}
	return rsCode{rsc}
}

type rsCode struct {
	reedsolomon.Encoder
}

func (rsc rsCode) Encode(data []byte) [][]byte {
	shards, err := rsc.Split(data)
	if err != nil {
		panic(err)
	} else if err := rsc.Encoder.Encode(shards); err != nil {
		panic(err)
	}
	return shards
}

func (rsc rsCode) Recover(w io.Writer, shards [][]byte, n int) error {
	if err := rsc.ReconstructData(shards); err != nil {
		return err
	}
	return rsc.Join(w, shards, n)
}

// simpleRedundancy implements the ErasureCoder interface when no
// parity shards are desired
type simpleRedundancy int

func (r simpleRedundancy) Encode(data []byte) [][]byte {
	// Calculate number of bytes per shard.
	perShard := len(data) / int(r)
	if int(r)*perShard < len(data) {
		perShard++
	}

	// If data isn't evenly divisible by r, we must pad it with zeros.
	if len(data) < int(r)*perShard {
		data = append(data, make([]byte, int(r)*perShard-len(data))...)
	}

	// Split into equal-length shards.
	dst := make([][]byte, r)
	b := bytes.NewBuffer(data)
	for i := range dst {
		dst[i] = b.Next(perShard)
	}
	return dst
}

func (r simpleRedundancy) Reconstruct(shards [][]byte) error {
	if len(shards) != int(r) {
		return reedsolomon.ErrTooFewShards
	}
	return nil
}

func (r simpleRedundancy) Recover(dst io.Writer, shards [][]byte, outSize int) error {
	if len(shards) != int(r) {
		return reedsolomon.ErrTooFewShards
	}
	remaining := outSize
	for _, shard := range shards {
		if remaining < len(shard) {
			shard = shard[:remaining]
		}
		n, err := dst.Write(shard)
		if err != nil {
			return err
		}
		remaining -= n
	}
	return nil
}
