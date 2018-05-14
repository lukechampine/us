package renter

import (
	"encoding/binary"
	"io"
	"os"

	"github.com/NebulousLabs/Sia/crypto"
	"github.com/pkg/errors"
)

// A SectorSlice is the unit element of a shard file. Each SectorSlice uniquely
// identifies a contiguous slice of data stored on a host.
type SectorSlice struct {
	MerkleRoot crypto.Hash
	Offset     uint32
	Length     uint32
	Checksum   crypto.Hash
}

// SectorSliceSize is the encoded size of a SectorSlice.
const SectorSliceSize = 32 + 4 + 4 + 32

// A Shard is a shard file open for writing.
type Shard struct {
	f   *os.File
	buf [SectorSliceSize]byte
}

// WriteSlice writes slice at the specified index, growing the underlying
// file as necessary.
func (s *Shard) WriteSlice(slice SectorSlice, index int64) error {
	if stat, err := s.f.Stat(); err != nil {
		return errors.Wrap(err, "could not stat shard")
	} else if stat.Size() < index*SectorSliceSize {
		// truncate Shard to appropriate size
		//
		// NOTE: for best performance, avoid this branch by writing slices
		// sequentially
		if err := s.f.Truncate(index * SectorSliceSize); err != nil {
			return errors.Wrap(err, "could not resize shard")
		}
	}

	// encode slice
	encSlice := s.buf[:]
	n := copy(encSlice[:], slice.MerkleRoot[:])
	binary.LittleEndian.PutUint32(encSlice[n:], slice.Offset)
	n += 4
	binary.LittleEndian.PutUint32(encSlice[n:], slice.Length)
	n += 4
	copy(encSlice[n:], slice.Checksum[:])

	// write slice
	if _, err := s.f.WriteAt(encSlice, index*SectorSliceSize); err != nil {
		return errors.Wrap(err, "could not write shard slice")
	}
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
	// truncate to multiple of SectorSliceSize
	if stat, err := file.Stat(); err != nil {
		return nil, errors.Wrap(err, "could not stat shard")
	} else if size := stat.Size(); size%SectorSliceSize != 0 {
		n := size / SectorSliceSize
		if err = file.Truncate(n * SectorSliceSize); err != nil {
			return nil, errors.Wrap(err, "could not repair shard")
		}
	}
	return &Shard{f: file}, nil
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
	buf := make([]byte, SectorSliceSize)
	for i := range slices {
		if _, err := io.ReadFull(f, buf); err != nil {
			return nil, errors.Wrap(err, "could not read shard")
		}
		n := copy(slices[i].MerkleRoot[:], buf)
		slices[i].Offset = binary.LittleEndian.Uint32(buf[n:])
		n += 4
		slices[i].Length = binary.LittleEndian.Uint32(buf[n:])
		n += 4
		copy(slices[i].Checksum[:], buf[n:])
	}
	return slices, nil
}
