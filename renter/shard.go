package renter

import (
	"bufio"
	"encoding/binary"
	"io"
	"os"
	"unsafe"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
)

// A SectorSlice is the unit element of a shard file. Each SectorSlice uniquely
// identifies a contiguous slice of data stored on a host.
type SectorSlice struct {
	MerkleRoot   crypto.Hash
	SegmentIndex uint32
	NumSegments  uint32
	Nonce        [24]byte
}

// SectorSliceSize is the encoded size of a SectorSlice.
const SectorSliceSize = 64

// assert that SectorSliceSize is accurate
var _ [SectorSliceSize]struct{} = [unsafe.Sizeof(SectorSlice{})]struct{}{}

// A Shard is a shard file open for writing.
type Shard struct {
	f         *os.File
	numSlices int64
}

// WriteSlice writes slice at the specified index, growing the underlying
// file as necessary.
func (s *Shard) WriteSlice(slice SectorSlice, index int64) error {
	if index > s.numSlices {
		// truncate Shard to appropriate size
		//
		// NOTE: for best performance, avoid this branch by writing slices
		// sequentially
		if err := s.f.Truncate(index * SectorSliceSize); err != nil {
			return errors.Wrap(err, "could not resize shard")
		}
		s.numSlices = index
	}

	// encode slice
	encSlice := make([]byte, SectorSliceSize)
	copy(encSlice, slice.MerkleRoot[:])
	binary.LittleEndian.PutUint32(encSlice[32:], slice.SegmentIndex)
	binary.LittleEndian.PutUint32(encSlice[36:], slice.NumSegments)
	copy(encSlice[40:], slice.Nonce[:])

	// write slice
	if _, err := s.f.WriteAt(encSlice, index*SectorSliceSize); err != nil {
		return errors.Wrap(err, "could not write shard slice")
	}
	s.numSlices++
	return nil
}

// Close closes the shard file.
func (s *Shard) Close() error {
	return s.f.Close()
}

// OpenShard opens a shard file for writing, creating it if necessary. If the
// file's size is not a multiple of SectorSliceSize, it is truncated
// accordingly.
func OpenShard(filename string) (*Shard, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return nil, errors.Wrap(err, "could not open shard for writing")
	}
	// determine number of slices in shard
	stat, err := file.Stat()
	if err != nil {
		return nil, errors.Wrap(err, "could not stat shard")
	}
	numSlices := stat.Size() / SectorSliceSize
	// if necessary, truncate to multiple of SectorSliceSize
	if numSlices*SectorSliceSize != stat.Size() {
		if err := file.Truncate(numSlices * SectorSliceSize); err != nil {
			return nil, errors.Wrap(err, "could not repair shard")
		}
	}
	return &Shard{
		f:         file,
		numSlices: numSlices,
	}, nil
}

// ReadShard loads the slices of a shard file into memory.
func ReadShard(filename string) ([]SectorSlice, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, errors.Wrap(err, "could not open shard for reading")
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return nil, errors.Wrap(err, "could not stat shard")
	}
	slices := make([]SectorSlice, stat.Size()/SectorSliceSize)
	bf := bufio.NewReader(f)
	buf := make([]byte, SectorSliceSize)
	for i := range slices {
		if _, err := io.ReadFull(bf, buf); err != nil {
			return nil, errors.Wrap(err, "could not read shard")
		}
		copy(slices[i].MerkleRoot[:], buf[:32])
		slices[i].SegmentIndex = binary.LittleEndian.Uint32(buf[32:36])
		slices[i].NumSegments = binary.LittleEndian.Uint32(buf[36:40])
		copy(slices[i].Nonce[:], buf[40:64])
	}
	return slices, nil
}
