package renterutil

import (
	"bytes"
	"io"
	"strings"
	"sync"

	"lukechampine.com/us/merkle"

	"github.com/pkg/errors"
	"lukechampine.com/us/renter"
)

// A PseudoFile presents a file-like interface for a metafile stored on Sia
// hosts.
type PseudoFile struct {
	m      renter.MetaIndex
	shards [][]renter.SectorSlice
	ds     *DownloaderSet
	offset int64
	mu     sync.Mutex // serializes all methods
}

func (f *PseudoFile) downloadShards(n int) ([][]byte, error) {
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
	// compute per-shard offset + length, padding to segment size
	start := (f.offset / int64(f.m.MinShards*merkle.SegmentSize)) * merkle.SegmentSize
	end := ((f.offset + int64(n)) / int64(f.m.MinShards*merkle.SegmentSize)) * merkle.SegmentSize
	if (f.offset+int64(n))%int64(f.m.MinShards*merkle.SegmentSize) != 0 {
		end += merkle.SegmentSize
	}
	return downloadRange(hosts, start, end-start, f.m.MinShards)
}

func downloadRange(hosts []*renter.ShardDownloader, offset, length int64, minShards int) (shards [][]byte, err error) {
	errNoHost := errors.New("no downloader for this host")
	type result struct {
		shardIndex int
		shard      []byte
		err        error
	}
	reqChan := make(chan int, minShards)
	resChan := make(chan result, minShards)
	var wg sync.WaitGroup
	reqIndex := 0
	for ; reqIndex < minShards; reqIndex++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for shardIndex := range reqChan {
				res := result{shardIndex: shardIndex}
				host := hosts[shardIndex]
				if host == nil {
					res.err = errNoHost
				} else {
					var buf bytes.Buffer
					res.err = host.CopySection(&buf, offset, length)
					res.err = errors.Wrap(res.err, host.HostKey().ShortKey())
					res.shard = buf.Bytes()
				}
				resChan <- res
			}
		}()
		reqChan <- reqIndex
	}
	defer func() {
		close(reqChan)
		wg.Wait()
	}()
	var goodRes, badRes []result
	for len(goodRes) < minShards && len(badRes) <= len(hosts)-minShards {
		res := <-resChan
		if res.err == nil {
			goodRes = append(goodRes, res)
		} else {
			badRes = append(badRes, res)
			if reqIndex < len(hosts) {
				reqChan <- reqIndex
				reqIndex++
			}
		}
	}
	if len(goodRes) < minShards {
		var errStrings []string
		for _, r := range badRes {
			if r.err != errNoHost {
				errStrings = append(errStrings, r.err.Error())
			}
		}
		return nil, errors.New("too many hosts did not supply their shard:\n" + strings.Join(errStrings, "\n"))
	}
	shards = make([][]byte, len(hosts))
	for _, r := range goodRes {
		shards[r.shardIndex] = r.shard
	}
	return shards, nil
}

type skipWriter struct {
	b    *bytes.Buffer
	skip int
}

func (sw *skipWriter) Write(p []byte) (int, error) {
	toSkip := sw.skip
	if toSkip > len(p) {
		toSkip = len(p)
	}
	sw.b.Write(p[toSkip:])
	sw.skip -= toSkip
	return len(p), nil
}

// Read implements io.Reader.
func (f *PseudoFile) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.offset >= f.m.Filesize {
		return 0, io.EOF
	}

	shards, err := f.downloadShards(len(p))
	if err != nil {
		return 0, err
	}

	// recover data shards directly into p
	skip := int(f.offset % merkle.SegmentSize)
	w := &skipWriter{bytes.NewBuffer(p[:0]), skip}
	writeLen := skip + len(p)
	if writeLen > int(f.m.Filesize-f.offset) {
		writeLen = int(f.m.Filesize - f.offset)
	}
	err = f.m.ErasureCode().Recover(w, shards, writeLen)
	if err != nil {
		return 0, errors.Wrap(err, "could not recover chunk")
	}
	f.offset += int64(writeLen)
	return writeLen, nil
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
	return &PseudoFile{
		m:      m.MetaIndex,
		shards: shards,
		ds:     downloaders,
	}, nil
}
