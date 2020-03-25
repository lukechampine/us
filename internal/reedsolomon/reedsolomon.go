// Package reedsolomon provides a Reed-Solomon erasure encoder.
package reedsolomon

import (
	"bytes"
	"errors"
	"io"
	"sync"

	"golang.org/x/sys/cpu"
)

var (
	useSSSE3 = cpu.X86.HasSSSE3
	useAVX2  = cpu.X86.HasAVX2

	// ErrInvShardNum will be returned by New, if you attempt to create an
	// Encoder where either data or parity shards is zero or less.
	ErrInvShardNum = errors.New("cannot create Encoder with zero or less data/parity shards")

	// ErrMaxShardNum will be returned by New, if you attempt to create an
	// Encoder where data and parity shards are bigger than the order of
	// GF(2^8).
	ErrMaxShardNum = errors.New("cannot create Encoder with more than 256 data+parity shards")

	// ErrTooFewShards is returned if too few shards were given to
	// Encode/Reconstruct. It will also be returned from Reconstruct if there
	// were too few shards to reconstruct the missing data.
	ErrTooFewShards = errors.New("too few shards given")

	// ErrShardNoData will be returned if there are no shards, or if the length
	// of all shards is zero.
	ErrShardNoData = errors.New("no shard data")

	// ErrShardSize is returned if shard length isn't the same for all shards.
	ErrShardSize = errors.New("shard sizes do not match")

	// ErrShortData will be returned by Split(), if there isn't enough data to
	// fill the number of shards.
	ErrShortData = errors.New("not enough data to fill the number of requested shards")

	// ErrReconstructRequired is returned if too few data shards are intact and
	// a reconstruction is required before you can successfully join the shards.
	ErrReconstructRequired = errors.New("reconstruction required as one or more required data shards are nil")
)

// ReedSolomon contains a matrix for a specific distribution of datashards and
// parity shards.
type ReedSolomon struct {
	DataShards   int
	ParityShards int
	shards       int // DataShards+ParityShards, for convenience
	m            matrix
	parity       [][]byte
}

// buildMatrix creates the matrix to use for encoding, given the number of data
// shards and the number of total shards.
//
// The top square of the matrix is guaranteed to be an identity matrix, which
// means that the data shards are unchanged after encoding.
func buildMatrix(dataShards, totalShards int) matrix {
	// Start with a Vandermonde matrix. This matrix would work, in theory, but
	// doesn't have the property that the data shards are unchanged after
	// encoding.
	vm := vandermonde(totalShards, dataShards)

	// Multiply by the inverse of the top square of the matrix. This will make
	// the top square be the identity matrix, but preserve the property that any
	// square subset of rows is invertible.
	top := vm.SubMatrix(0, 0, dataShards, dataShards)
	topInv, _ := top.Invert()
	return vm.Multiply(topInv)
}

// New returns an Encoder with the specified number of shards.
func New(dataShards, parityShards int) (*ReedSolomon, error) {
	r := &ReedSolomon{
		DataShards:   dataShards,
		ParityShards: parityShards,
		shards:       dataShards + parityShards,
	}
	if dataShards <= 0 || parityShards <= 0 {
		return nil, ErrInvShardNum
	}

	if uint64(dataShards)+uint64(parityShards) > 256 {
		return nil, ErrMaxShardNum
	}

	r.m = buildMatrix(dataShards, r.shards)
	r.parity = make([][]byte, parityShards)
	for i := range r.parity {
		r.parity[i] = r.m[dataShards+i]
	}

	return r, nil
}

// Encode encodes parity for a set of shards. The number of shards must match
// the number given to New, and each shard must have the same capacity. The data
// in the first r.DataShards elements will be used to generate parity, which is
// written into the remaining elements.
func (r *ReedSolomon) Encode(shards [][]byte) error {
	if len(shards) != r.shards {
		return ErrTooFewShards
	}
	err := checkShards(shards, false)
	if err != nil {
		return err
	}
	r.codeSomeShardsP(r.parity, shards[:r.DataShards], shards[r.DataShards:], len(shards[0]))
	return nil
}

// codeSomeShardsP multiplies, in parallel, a subset of rows from a coding
// matrix by a full set of input shards to produce some output shards.
func (r *ReedSolomon) codeSomeShardsP(matrixRows, inputs, outputs [][]byte, byteCount int) {
	const maxGoroutines = 384
	const minSplitSize = 1024
	var wg sync.WaitGroup
	do := byteCount / maxGoroutines
	if do < minSplitSize {
		do = minSplitSize
	}
	// Make sizes divisible by 32
	do = (do + 31) & (^31)
	start := 0
	for start < byteCount {
		if start+do > byteCount {
			do = byteCount - start
		}
		wg.Add(1)
		go func(start, stop int) {
			for c := 0; c < r.DataShards; c++ {
				in := inputs[c][start:stop]
				for iRow, out := range outputs {
					if c == 0 {
						galMulSlice(matrixRows[iRow][c], in, out[start:stop], useSSSE3, useAVX2)
					} else {
						galMulSliceXor(matrixRows[iRow][c], in, out[start:stop], useSSSE3, useAVX2)
					}
				}
			}
			wg.Done()
		}(start, start+do)
		start += do
	}
	wg.Wait()
}

// checkShards checks if shards are the same size.
func checkShards(shards [][]byte, nilok bool) error {
	size := shardSize(shards)
	if size == 0 {
		return ErrShardNoData
	}
	for _, shard := range shards {
		if len(shard) != size {
			if len(shard) != 0 || !nilok {
				return ErrShardSize
			}
		}
	}
	return nil
}

// shardSize return the size of a single shard. The first non-zero size is
// returned, or 0 if all shards are size 0.
func shardSize(shards [][]byte) int {
	for _, shard := range shards {
		if len(shard) != 0 {
			return len(shard)
		}
	}
	return 0
}

// Reconstruct recreates missing data and parity shards, if possible. The input
// should match the input to Encode, with missing shards resliced to have a
// length of 0 (but sufficient capacity to hold a recreated shard).
//
// Reconstruct does not check the integrity of the data; if the input shards do
// not match the shards passed to Encode, it will produce garbage.
func (r *ReedSolomon) Reconstruct(shards [][]byte) error {
	return r.reconstruct(shards, false)
}

// ReconstructData is like Reconstruct, but only recreates missing data shards.
func (r *ReedSolomon) ReconstructData(shards [][]byte) error {
	return r.reconstruct(shards, true)
}

func (r *ReedSolomon) reconstruct(shards [][]byte, dataOnly bool) error {
	if len(shards) != r.shards {
		return ErrTooFewShards
	}
	err := checkShards(shards, true)
	if err != nil {
		return err
	}

	shardSize := shardSize(shards)

	// Quick check: are all of the shards present (or, if dataOnly, all of the
	// data shards)? If so, there's nothing to do.
	numberPresent := 0
	dataPresent := 0
	for i := 0; i < r.shards; i++ {
		if len(shards[i]) != 0 {
			numberPresent++
			if i < r.DataShards {
				dataPresent++
			}
		}
	}
	if numberPresent == r.shards || (dataOnly && dataPresent == r.DataShards) {
		return nil
	}
	if numberPresent < r.DataShards {
		return ErrTooFewShards
	}

	// Pull out an array holding just the shards that correspond to the rows of
	// the submatrix. These shards will be the input to the decoding process
	// that recreates the missing data shards.
	//
	// Also, create an array of indices of the valid rows we do have.
	subShards := make([][]byte, 0, 256)
	validIndices := make([]int, 0, 256)
	for matrixRow := 0; matrixRow < r.shards && len(validIndices) < r.DataShards; matrixRow++ {
		if len(shards[matrixRow]) != 0 {
			subShards = append(subShards, shards[matrixRow])
			validIndices = append(validIndices, matrixRow)
		}
	}

	// Pull out the rows of the matrix that correspond to the shards that we
	// have and build a square matrix. This matrix could be used to generate
	// the shards that we have from the original data.
	subMatrix := newMatrix(r.DataShards, r.DataShards)
	for subMatrixRow, validIndex := range validIndices {
		for c := 0; c < r.DataShards; c++ {
			subMatrix[subMatrixRow][c] = r.m[validIndex][c]
		}
	}
	// Invert the matrix, so we can go from the encoded shards back to the
	// original data. Then pull out the row that generates the shard that we
	// want to decode. Note that since this matrix maps back to the original
	// data, it can be used to create a data shard, but not a parity shard.
	dataDecodeMatrix, err := subMatrix.Invert()
	if err != nil {
		return err
	}

	// Re-create any data shards that were missing.
	//
	// The input to the coding is all of the shards we actually have, and the
	// output is the missing data shards. The computation is done using the
	// special decode matrix we just built.
	outputs := make([][]byte, 0, r.shards)
	matrixRows := make([][]byte, 0, r.shards)
	for iShard := 0; iShard < r.DataShards; iShard++ {
		if len(shards[iShard]) == 0 {
			shards[iShard] = shards[iShard][:shardSize]
			outputs = append(outputs, shards[iShard])
			matrixRows = append(matrixRows, dataDecodeMatrix[iShard])
		}
	}
	r.codeSomeShardsP(matrixRows, subShards, outputs, shardSize)

	if dataOnly {
		return nil
	}

	// Now that we have all of the data shards intact, we can compute any of the
	// parity that is missing.
	//
	// The input to the coding is ALL of the data shards, including any that we
	// just calculated. The output is whichever of the data shards were missing.
	outputs, matrixRows = outputs[:0], matrixRows[:0]
	for iShard := r.DataShards; iShard < r.shards; iShard++ {
		if len(shards[iShard]) == 0 {
			shards[iShard] = shards[iShard][:shardSize]
			outputs = append(outputs, shards[iShard])
			matrixRows = append(matrixRows, r.parity[iShard-r.DataShards])
		}
	}
	r.codeSomeShardsP(matrixRows, shards[:r.DataShards], outputs, shardSize)
	return nil
}

// SplitMulti splits data into blocks of shards, where each block has subsize
// bytes. The shards must have sufficient capacity to hold the sharded data. The
// length of the shards will be modified to fit their new contents.
func (r *ReedSolomon) SplitMulti(data []byte, shards [][]byte, subsize int) error {
	chunkSize := r.DataShards * subsize
	numChunks := len(data) / chunkSize
	if len(data)%chunkSize != 0 {
		numChunks++
	}

	// extend shards to proper len
	shardSize := numChunks * subsize
	for i := range shards {
		if cap(shards[i]) < shardSize {
			return errors.New("each shard must have capacity of at least len(data)/m")
		}
		shards[i] = shards[i][:shardSize]
	}

	// copy data into first DataShards shards, subsize bytes at a time
	buf := bytes.NewBuffer(data)
	for off := 0; buf.Len() > 0; off += subsize {
		for i := 0; i < r.DataShards; i++ {
			copy(shards[i][off:], buf.Next(subsize))
		}
	}

	return nil
}

// JoinMulti joins the supplied multi-block shards, writing them to dst. The
// first 'skip' bytes of the recovered data are skipped, and 'writeLen' bytes
// are written in total.
func (r *ReedSolomon) JoinMulti(dst io.Writer, shards [][]byte, subsize, skip, writeLen int) error {
	// Do we have enough shards?
	if len(shards) < r.DataShards {
		return ErrTooFewShards
	}
	shards = shards[:r.DataShards]

	// Do we have enough data?
	size := 0
	for _, shard := range shards {
		if len(shard) == 0 {
			return ErrReconstructRequired
		}
		size += len(shard)
		if size >= writeLen {
			break
		}
	}
	if size < writeLen {
		return ErrShortData
	}

	// Copy data to dst.
	for off := 0; writeLen > 0; off += subsize {
		for _, shard := range shards {
			shard = shard[off:][:subsize]
			if skip >= len(shard) {
				skip -= len(shard)
				continue
			} else if skip > 0 {
				shard = shard[skip:]
				skip = 0
			}
			if writeLen < len(shard) {
				shard = shard[:writeLen]
			}
			n, err := dst.Write(shard)
			if err != nil {
				return err
			}
			writeLen -= n
		}
	}
	return nil
}
