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
	// static fields
	m             renter.MetaIndex
	shards        [][]renter.SectorSlice
	ds            *DownloaderSet
	lastChunkSize int64

	// dynamic fields
	buf         bytes.Buffer
	offset      int64 // current offset within file
	chunk       int64 // current chunk index
	chunkOffset int64 // current offset within chunk

	mu sync.Mutex
}

func (f *PseudoFile) calculateChunkOffset(offset int64) (chunkIndex, chunkOffset int64) {
	if len(f.shards) == 0 {
		return -1, -1
	}
	rem := offset
	for i, s := range f.shards[0] {
		chunkSize := int64(s.NumSegments*merkle.SegmentSize) * int64(f.m.MinShards)
		if rem < chunkSize {
			return int64(i), rem
		}
		rem -= chunkSize
	}
	return -1, -1
}

func (f *PseudoFile) downloadChunk(chunk int64) error {
	if chunk >= int64(len(f.shards[0])) {
		return io.EOF
	}
	hosts := make([]*renter.ShardDownloader, len(f.m.Hosts))
	for i, hostKey := range f.m.Hosts {
		d, ok := f.ds.acquire(hostKey)
		if !ok {
			continue
		}
		defer f.ds.release(hostKey)
		hosts[i] = &renter.ShardDownloader{
			Downloader: d,
			Key:        f.m.MasterKey,
			Slices:     f.shards[i],
		}
	}
	shards, shardLen, _, err := DownloadChunkShards(hosts, chunk, f.m.MinShards, nil)
	if err != nil {
		return err
	}

	// reconstruct missing shards and write to buffer
	f.buf.Reset()
	writeLen := shardLen * f.m.MinShards
	if chunk == int64(len(f.shards[0])-1) {
		// last chunk is a special case
		writeLen = int(f.lastChunkSize)
	}
	err = f.m.ErasureCode().Recover(&f.buf, shards, writeLen)
	if err != nil {
		return errors.Wrap(err, "could not recover sector")
	}
	return nil
}

// Read implements io.Reader.
func (f *PseudoFile) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.offset >= f.m.Filesize {
		return 0, io.EOF
	}
	if f.chunkOffset >= int64(f.buf.Len()) {
		if err := f.downloadChunk(f.chunk); err != nil {
			return 0, err
		}
		f.chunk++
		f.chunkOffset = 0
	}
	buf := f.buf.Bytes()
	n := copy(p, buf[f.chunkOffset:])
	f.chunkOffset += int64(n)
	f.offset += int64(n)
	return n, nil
}

// Seek implements io.Seeker.
func (f *PseudoFile) Seek(offset int64, whence int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	newOffset := f.offset
	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset += offset
	case io.SeekEnd:
		newOffset = f.m.Filesize - offset
	}
	if newOffset < 0 {
		return 0, errors.New("seek position cannot be negative")
	}
	f.offset = newOffset
	oldChunk := f.chunk
	f.chunk, f.chunkOffset = f.calculateChunkOffset(newOffset)
	if f.chunk != oldChunk {
		f.buf.Reset()
	}
	return f.offset, nil
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
	// determine lastChunkSize
	lastChunkSize := m.Filesize
	for _, s := range shards[0][:len(shards[0])-1] {
		lastChunkSize -= int64(s.NumSegments*merkle.SegmentSize) * int64(m.MinShards)
	}
	return &PseudoFile{
		m:             m.MetaIndex,
		shards:        shards,
		ds:            downloaders,
		chunk:         0,
		lastChunkSize: lastChunkSize,
	}, nil
}
