package renterutil

import (
	"bufio"
	"io"
	"os"
	"strings"
	"sync"

	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renterhost"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
)

// Download downloads m to f, updating the specified contracts. Download may
// write to f in parallel.
func Download(f *os.File, contracts renter.ContractSet, m *renter.MetaFile, hkr renter.HostKeyResolver) *Operation {
	op := newOperation()
	go download(op, f, contracts, m, hkr)
	return op
}

func download(op *Operation, f *os.File, contracts renter.ContractSet, m *renter.MetaFile, hkr renter.HostKeyResolver) {
	if err := f.Chmod(m.Mode); err != nil {
		op.die(errors.Wrap(err, "could not set file mode"))
		return
	}

	// check if file is already partially or fully downloaded; if so, resume
	// from last incomplete chunk
	chunkIndex, bytesVerified, err := func() (int, int64, error) {
		stat, err := f.Stat()
		if err != nil {
			return 0, 0, errors.Wrap(err, "could not stat file")
		} else if stat.Size() == 0 {
			return 0, 0, nil
		} else if stat.Size() > m.Filesize {
			if err := f.Truncate(m.Filesize); err != nil {
				return 0, 0, errors.Wrap(err, "could not resize file")
			}
		}

		shards := make([][]renter.SectorSlice, m.MinShards)
		for i := range shards {
			shard, err := renter.ReadShard(m.ShardPath(m.Hosts[i]))
			if err != nil {
				return 0, 0, errors.Wrap(err, "could not read shard")
			}
			shards[i] = shard
		}

		buf := make([]byte, 0, renterhost.SectorSize)
		var bytesVerified int64
		for chunkIndex := range shards[0] {
			for i := range shards {
				s := shards[i][chunkIndex]
				buf = buf[:s.NumSegments*merkle.SegmentSize]
				_, err := io.ReadFull(f, buf)
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					return chunkIndex, bytesVerified, nil
				} else if err != nil {
					return 0, 0, errors.Wrap(err, "could not verify file contents")
				}
				if crypto.HashBytes(buf) != s.Checksum {
					return chunkIndex, bytesVerified, nil
				}
				bytesVerified += int64(len(buf))
			}
		}
		// fully verified
		return -1, 0, nil
	}()
	if err != nil {
		op.die(err)
		return
	} else if chunkIndex == -1 {
		// nothing to do
		op.die(nil)
		return
	}

	// set seek position to end of last good chunk
	if _, err := f.Seek(bytesVerified, io.SeekStart); err != nil {
		op.die(errors.Wrap(err, "could not seek to end of verified content"))
		return
	}

	downloadStream(op, f, int64(chunkIndex), contracts, m, hkr)
}

// DownloadStream writes the contents of m to w.
func DownloadStream(w io.Writer, contracts renter.ContractSet, m *renter.MetaFile, hkr renter.HostKeyResolver) *Operation {
	op := newOperation()
	go downloadStream(op, w, 0, contracts, m, hkr)
	return op
}

func downloadStream(op *Operation, w io.Writer, chunkIndex int64, contracts renter.ContractSet, m *renter.MetaFile, hkr renter.HostKeyResolver) {
	// connect to hosts in parallel
	hosts, err := dialDownloaders(m, contracts, hkr, op.cancel)
	if err != nil {
		op.die(err)
		return
	}
	for _, h := range hosts {
		if h != nil {
			defer h.Close()
			op.sendUpdate(DialStatsUpdate{
				Host:  h.HostKey(),
				Stats: h.Downloader.DialStats(),
			})
		}
	}

	// calculate download offset
	var offset int64
	for _, h := range hosts {
		if h == nil {
			continue
		}
		for _, s := range h.Slices[:chunkIndex] {
			offset += int64(s.NumSegments) * merkle.SegmentSize * int64(m.MinShards)
		}
		break
	}
	remaining := m.Filesize - offset

	// send initial progress
	op.sendUpdate(TransferProgressUpdate{
		Total:       m.Filesize,
		Start:       offset,
		Transferred: 0,
	})

	// download in parallel
	bw := bufio.NewWriter(w)
	rsc := m.ErasureCode()
	for remaining > 0 {
		if op.Canceled() {
			op.die(ErrCanceled)
			return
		}

		// download shards of the chunk in parallel
		shards, shardLen, stats, err := DownloadChunkShards(hosts, chunkIndex, m.MinShards, op.cancel)
		if err != nil {
			op.die(err)
			return
		}
		// send download stats
		for _, s := range stats {
			op.sendUpdate(s)
		}

		// reconstruct missing data shards and write to file
		writeLen := int64(shardLen * m.MinShards)
		if writeLen > remaining {
			writeLen = remaining
		}
		err = rsc.Recover(bw, shards, int(writeLen))
		if err != nil {
			op.die(err)
			return
		}
		remaining -= writeLen
		op.sendUpdate(TransferProgressUpdate{
			Total:       m.Filesize,
			Start:       offset,
			Transferred: m.Filesize - offset - remaining,
		})
		chunkIndex++
	}
	if err := bw.Flush(); err != nil {
		op.die(err)
		return
	}
	op.die(nil)
}

// DownloadDir downloads the metafiles in a directory, writing their contents
// to a set of files whose structure mirrors the metafile directory.
func DownloadDir(nextFile FileIter, contracts renter.ContractSet, hkr renter.HostKeyResolver) *Operation {
	op := newOperation()
	go downloadDir(op, nextFile, contracts, hkr)
	return op
}

func downloadDir(op *Operation, nextFile FileIter, contracts renter.ContractSet, hkr renter.HostKeyResolver) {
	for {
		metaPath, filePath, err := nextFile()
		if err == io.EOF {
			break
		} else if err != nil {
			op.sendUpdate(DirSkipUpdate{Filename: metaPath, Err: err})
			continue
		}
		err = func() error {
			canDownload, err := renter.MetaFileCanDownload(metaPath)
			if err != nil {
				return err
			} else if !canDownload {
				return errors.New("file is not sufficiently uploaded")
			}

			f, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR, 0666)
			if err != nil {
				return err
			}
			defer f.Close()
			defer func() {
				// if we didn't download anything, delete the file
				if stat, statErr := f.Stat(); statErr == nil && stat.Size() == 0 {
					os.RemoveAll(f.Name())
				}
			}()

			m, err := renter.OpenMetaFile(metaPath)
			if err != nil {
				return err
			}
			defer m.Close()

			op.sendUpdate(DirQueueUpdate{Filename: metaPath, Filesize: m.Filesize})

			dop := Download(f, contracts, m, hkr)
			// cancel dop if op is canceled
			done := make(chan struct{})
			defer close(done)
			go func() {
				select {
				case <-op.cancel:
					dop.Cancel()
				case <-done:
				}
			}()
			// forward dop updates to op
			for u := range dop.Updates() {
				op.sendUpdate(u)
			}
			return dop.Err()
		}()
		if err != nil {
			op.sendUpdate(DirSkipUpdate{Filename: metaPath, Err: err})
		}
	}
	op.die(nil)
}

func dialDownloaders(m *renter.MetaFile, contracts renter.ContractSet, hkr renter.HostKeyResolver, cancel <-chan struct{}) ([]*renter.ShardDownloader, error) {
	type result struct {
		shardIndex int
		host       *renter.ShardDownloader
		err        error
	}
	resChan := make(chan result, len(m.Hosts))
	for i := range m.Hosts {
		go func(i int) {
			hostKey := m.Hosts[i]
			res := result{shardIndex: i}
			contract, ok := contracts[hostKey]
			if !ok {
				res.err = errors.Errorf("%v: no contract for host", hostKey.ShortKey())
			} else {
				res.host, res.err = renter.NewShardDownloader(m, contract, hkr)
			}
			resChan <- res
		}(i)
	}

	hosts := make([]*renter.ShardDownloader, len(m.Hosts))
	var errStrings []string
	for range hosts {
		select {
		case res := <-resChan:
			if res.err != nil {
				errStrings = append(errStrings, res.err.Error())
			} else {
				hosts[res.shardIndex] = res.host
			}
		case <-cancel:
			for _, h := range hosts {
				if h != nil {
					h.Close()
				}
			}
			return nil, ErrCanceled
		}
	}
	if len(m.Hosts)-len(errStrings) < m.MinShards {
		for _, h := range hosts {
			if h != nil {
				h.Close()
			}
		}
		return nil, errors.New("couldn't connect to enough hosts:\n" + strings.Join(errStrings, "\n"))
	}

	return hosts, nil
}

// DownloadChunkShards downloads the shards of chunkIndex from hosts in
// parallel. shardLen is the length of the first non-nil shard.
//
// The shards returned by DownloadChunkShards are only valid until the next
// call to Sector on the shard's corresponding proto.Downloader.
func DownloadChunkShards(hosts []*renter.ShardDownloader, chunkIndex int64, minShards int, cancel <-chan struct{}) (shards [][]byte, shardLen int, stats []DownloadStatsUpdate, err error) {
	errNoHost := errors.New("no downloader for this host")
	type result struct {
		shardIndex int
		shard      []byte
		stats      DownloadStatsUpdate
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
					res.shard, res.err = host.DownloadAndDecrypt(chunkIndex)
					res.err = errors.Wrap(res.err, host.HostKey().ShortKey())
					res.stats = DownloadStatsUpdate{
						Host:  host.HostKey(),
						Stats: host.Downloader.LastDownloadStats(),
					}
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
		select {
		case <-cancel:
			return nil, 0, nil, ErrCanceled

		case res := <-resChan:
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
	}
	if len(goodRes) < minShards {
		var errStrings []string
		for _, r := range badRes {
			if r.err != errNoHost {
				errStrings = append(errStrings, r.err.Error())
			}
		}
		return nil, 0, nil, errors.New("too many hosts did not supply their shard:\n" + strings.Join(errStrings, "\n"))
	}

	shards = make([][]byte, len(hosts))
	stats = make([]DownloadStatsUpdate, 0, len(goodRes))
	for _, r := range goodRes {
		shards[r.shardIndex] = r.shard
		stats = append(stats, r.stats)
	}

	// determine shardLen
	for _, s := range shards {
		if len(s) > 0 {
			shardLen = len(s)
			break
		}
	}

	// allocate space for missing shards, in case the caller wants to
	// reconstruct them
	for i := range shards {
		if len(shards[i]) == 0 {
			shards[i] = make([]byte, 0, shardLen)
		}
	}

	return shards, shardLen, stats, nil
}
