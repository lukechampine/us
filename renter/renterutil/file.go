package renterutil

import (
	"bytes"
	"io"
	"sync"

	"github.com/pkg/errors"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renter"
)

// A PseudoFile presents a file-like interface for a metafile stored on Sia
// hosts.
type PseudoFile struct {
	mu sync.Mutex
	dr *downloadReader
}

// Read implements io.Reader.
func (f *PseudoFile) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dr.Read(p)
}

// Seek implements io.Seeker.
func (f *PseudoFile) Seek(offset int64, whence int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dr.Seek(offset, whence)
}

// NewPseudoFile returns a PseudoFile for the specified metafile.
func NewPseudoFile(m *renter.MetaFile, downloaders *DownloaderSet) (*PseudoFile, error) {
	shards := make([][]renter.SectorSlice, len(m.Hosts))
	for i := range m.Hosts {
		shard, err := renter.ReadShard(m.ShardPath(m.Hosts[i]))
		if err != nil {
			return nil, errors.Wrap(err, "could not read shard")
		}
		shards[i] = shard
	}
	dr, err := newDownloadReader(m.MetaIndex, shards, downloaders)
	if err != nil {
		return nil, errors.Wrap(err, "could not connect to hosts")
	}
	return &PseudoFile{
		dr: dr,
	}, nil
}

type downloadReader struct {
	m             renter.MetaIndex
	shards        [][]renter.SectorSlice
	ds            *DownloaderSet
	buf           bytes.Buffer
	lastChunkSize int64

	offset      int64 // current offset within file
	chunk       int64 // current chunk index
	chunkOffset int64 // current offset within chunk
}

func (dr *downloadReader) Seek(offset int64, whence int) (int64, error) {
	newOffset := dr.offset
	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset += offset
	case io.SeekEnd:
		newOffset = dr.m.Filesize - offset
	}
	if newOffset < 0 {
		return 0, errors.New("seek position cannot be negative")
	}
	dr.offset = newOffset
	dr.chunk, dr.chunkOffset = dr.calculateChunkOffset(newOffset)
	return dr.offset, nil
}

func (dr *downloadReader) Read(p []byte) (total int, err error) {
	if dr.offset >= dr.m.Filesize {
		return 0, io.EOF
	}
	if dr.chunkOffset >= int64(dr.buf.Len()) {
		err = dr.downloadChunk(dr.chunk)
		if err != nil {
			return 0, err
		}
		dr.chunk++
		dr.chunkOffset = 0
	}
	buf := dr.buf.Bytes()
	n := copy(p, buf[dr.chunkOffset:])
	dr.chunkOffset += int64(n)
	dr.offset += int64(n)
	return n, nil
}

func (dr *downloadReader) downloadChunk(chunk int64) error {
	if chunk >= int64(len(dr.shards[0])) {
		return io.EOF
	}
	hosts := make([]*renter.ShardDownloader, len(dr.m.Hosts))
	for i, hostKey := range dr.m.Hosts {
		d, ok := dr.ds.acquire(hostKey)
		if !ok {
			continue
		}
		defer dr.ds.release(hostKey)
		hosts[i] = &renter.ShardDownloader{
			Downloader: d,
			Key:        dr.m.EncryptionKey(i),
			Slices:     dr.shards[i],
		}
	}
	shards, shardLen, _, err := DownloadChunkShards(hosts, chunk, dr.m.MinShards, nil)
	if err != nil {
		return err
	}

	// reconstruct missing shards and write to buffer
	dr.buf.Reset()
	writeLen := shardLen * dr.m.MinShards
	if chunk == int64(len(dr.shards[0])-1) {
		// last chunk is a special case
		writeLen = int(dr.lastChunkSize)
	}
	err = dr.m.ErasureCode().Recover(&dr.buf, shards, writeLen)
	if err != nil {
		return errors.Wrap(err, "could not recover sector")
	}
	return nil
}

func (dr *downloadReader) calculateChunkOffset(offset int64) (chunkIndex, chunkOffset int64) {
	if len(dr.shards) == 0 {
		return -1, -1
	}
	rem := offset
	for i, s := range dr.shards[0] {
		chunkSize := int64(s.NumSegments*merkle.SegmentSize) * int64(dr.m.MinShards)
		if rem < chunkSize {
			return int64(i), rem
		}
		rem -= chunkSize
	}
	return -1, -1
}

func newDownloadReader(m renter.MetaIndex, shards [][]renter.SectorSlice, ds *DownloaderSet) (*downloadReader, error) {
	// determine lastChunkSize
	lastChunkSize := m.Filesize
	for _, s := range shards[0][:len(shards[0])-1] {
		lastChunkSize -= int64(s.NumSegments*merkle.SegmentSize) * int64(m.MinShards)
	}
	return &downloadReader{
		m:             m,
		shards:        shards,
		ds:            ds,
		chunk:         0,
		lastChunkSize: lastChunkSize,
	}, nil
}
