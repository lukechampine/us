package renterutil

import (
	"bytes"
	"io"
	"strings"
	"sync"

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
	offset := f.offset / int64(f.m.MinShards)
	if offset%64 != 0 {
		offset += 64 - (offset % 64)
	}
	length := int64(n / f.m.MinShards)
	if length%64 != 0 {
		length += 64 - (length % 64)
	}
	return downloadRange(hosts, offset, length, f.m.MinShards)
}

func downloadRange(hosts []*renter.ShardDownloader, offset, length int64, minShards int) (shards [][]byte, err error) {
	errNoHost := errors.New("no downloader for this host")
	type result struct {
		shardIndex int
		shard      []byte
		err        error
	}
	// spawn minShards goroutines that receive download requests from
	// reqChan and send responses to resChan.
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
		// prepopulate reqChan with first minShards shards
		reqChan <- reqIndex
	}
	// make sure all goroutines exit before returning
	defer func() {
		close(reqChan)
		wg.Wait()
	}()

	// collect the results of each shard download, appending successful
	// downloads to goodRes and failed downloads to badRes. If a download
	// fails, send the next untried shard index. Break as soon as we have
	// minShards successful downloads or if the number of failures makes it
	// impossible to recover the chunk.
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
	buf := bytes.NewBuffer(p[:0])
	writeLen := len(p)
	if writeLen > int(f.m.Filesize-f.offset) {
		writeLen = int(f.m.Filesize - f.offset)
	}
	err = f.m.ErasureCode().Recover(buf, shards, writeLen)
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
