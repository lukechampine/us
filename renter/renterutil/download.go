package renterutil

import (
	"bufio"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/blake2b"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renterhost"

	"github.com/pkg/errors"
)

// Download downloads m to f, updating the specified contracts. Download may
// write to f in parallel.
func Download(f *os.File, contracts renter.ContractSet, m *renter.MetaFile, hkr renter.HostKeyResolver) *Operation {
	op := newOperation()
	go download(op, f, contracts, m, hkr)
	return op
}

func download(op *Operation, f *os.File, contracts renter.ContractSet, m *renter.MetaFile, hkr renter.HostKeyResolver) {
	// check/set file mode and size
	{
		stat, err := f.Stat()
		if err != nil {
			op.die(errors.Wrap(err, "could not stat file"))
			return
		}
		if stat.Mode() != m.Mode {
			if err := f.Chmod(m.Mode); err != nil {
				op.die(errors.Wrap(err, "could not set file mode"))
				return
			}
		}
		if m.Filesize == 0 {
			// nothing to download
			op.die(nil)
			return
		} else if stat.Size() != m.Filesize {
			// we'll be writing to random offsets within the file in parallel, so
			// truncate it to the full size up-front
			if err := f.Truncate(m.Filesize); err != nil {
				op.die(errors.Wrap(err, "could not resize file"))
				return
			}
		}
	}

	// track metadata of each chunk in the file
	type shardStatus byte
	const (
		shardMissing = iota
		shardInProgress
		shardFinished
	)
	type chunkEntry struct {
		done       bool
		shards     [][]byte
		status     []shardStatus
		errs       []string
		fileOffset int64
		chunkSize  int64
	}
	var chunks []chunkEntry

	// Read through each chunk of the file and initialize chunks accordingly.
	// This lets us avoid redownloading any chunks already present on disk.
	{
		// To determine the size of each chunk, we need the sector slices of the
		// Shards. We can assume that the size of each slice is the same across
		// each Shard.
		slices := make([][]renter.SectorSlice, m.MinShards)
		for i := range slices {
			shard, err := renter.ReadShard(m.ShardPath(m.Hosts[i]))
			if err != nil {
				op.die(errors.Wrap(err, "could not read shard"))
				return
			}
			slices[i] = shard
		}
		chunks = make([]chunkEntry, len(slices[0]))

		// Before verifying the checksums, we have to recreate the erasure-
		// encoding of the file. Since we're only looking at the data pieces,
		// we can use an m-of-m code.
		rsc := renter.NewRSCode(m.MinShards, m.MinShards)
		chunk := make([]byte, 0, renterhost.SectorSize*m.MinShards)
		dataShards := make([][]byte, m.MinShards)
		for i := range dataShards {
			dataShards[i] = make([]byte, 0, renterhost.SectorSize)
		}
		var fileOffset int64
		for chunkIndex := range chunks {
			c := &chunks[chunkIndex]
			c.fileOffset = fileOffset
			c.chunkSize = int64(slices[0][chunkIndex].NumSegments) * merkle.SegmentSize * int64(m.MinShards)
			if fileOffset+c.chunkSize > m.Filesize {
				c.chunkSize = m.Filesize - fileOffset
			}
			fileOffset += c.chunkSize
			buf := chunk[:c.chunkSize]
			_, err := io.ReadFull(f, buf)
			if err != nil {
				// technically we don't need to terminate here, but in practice
				// if the read fails, later writes will fail too, so might as
				// well fail early
				op.die(errors.Wrap(err, "couldn't verify file contents"))
				return
			}
			rsc.Encode(buf, dataShards)
			c.done = true
			for i, shard := range dataShards {
				c.done = c.done && (blake2b.Sum256(shard) == slices[i][chunkIndex].Checksum)
			}
			if !c.done {
				c.status = make([]shardStatus, len(m.Hosts))
			}
		}
	}
	// calculate how many bytes are left to download
	remaining := m.Filesize
	for _, c := range chunks {
		if c.done {
			remaining -= c.chunkSize
		}
	}
	if remaining == 0 {
		op.die(nil)
		return
	}

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

	// send initial progress
	initialBytes := m.Filesize - remaining
	transferred := int64(0)
	op.sendUpdate(TransferProgressUpdate{
		Total:       m.Filesize,
		Start:       initialBytes,
		Transferred: transferred,
	})

	// Begin downloading in parallel. The basic algorithm is as follows:
	//
	// Each host has a worker goroutine that searches for unfinished chunks that
	// are missing its shard, downloads that shard, and sends it down a shared
	// channel. The main goroutine receives the shards, assembles them into
	// finished chunks, writes them to disk, and marks the chunk as done. This
	// process continues until all chunks have been downloaded.

	// First, define a helper function that searches for work, returning an
	// unfinished chunk that does not have the specified shard (or false if
	// there are no such chunks).
	var workMu sync.Mutex
	chunkCond := sync.NewCond(&workMu)
	getWork := func(shardIndex int) (chunkIndex int64, ok bool) {
		if op.Canceled() {
			return -1, false
		}
		workMu.Lock()
		for chunkIndex := range chunks {
			c := &chunks[chunkIndex]
			if c.done || c.status[shardIndex] != shardMissing {
				continue
			}
			shardsNeeded := m.MinShards
			for _, s := range c.status {
				if s != shardMissing {
					shardsNeeded--
				}
			}
			if shardsNeeded > 0 {
				c.status[shardIndex] = shardInProgress
				// Wait for the main goroutine to give us a buffer to download
				// into. This bounds the total number of shards we hold in
				// memory at any given time.
				for c.shards == nil {
					chunkCond.Wait()
				}
				workMu.Unlock()
				return int64(chunkIndex), true
			}
		}
		workMu.Unlock()
		return -1, false
	}

	// allocate memory for the first four chunks
	{
		allocated := 0
		for i := range chunks {
			c := &chunks[i]
			if c.done {
				continue
			}
			c.shards = make([][]byte, len(m.Hosts))
			for j := range c.shards {
				c.shards[j] = make([]byte, 0, renterhost.SectorSize)
			}
			if allocated++; allocated >= 4 {
				break
			}
		}
	}

	// create consumer channel
	type shardRes struct {
		chunk int64
		shard int
		stats DownloadStatsUpdate
		err   error
	}
	shardChan := make(chan shardRes, len(hosts))

	// spawn a goroutine for each host
	for i := range hosts {
		if hosts[i] == nil {
			continue
		}
		go func(i int) {
			host := hosts[i]
			for {
				chunkIndex, ok := getWork(i)
				if !ok {
					return
				}
				shard, err := host.DownloadAndDecrypt(chunkIndex)
				chunks[chunkIndex].shards[i] = append(chunks[chunkIndex].shards[i][:0], shard...)
				shardChan <- shardRes{
					chunk: chunkIndex,
					shard: i,
					stats: DownloadStatsUpdate{
						Host:  host.HostKey(),
						Stats: host.Downloader.LastDownloadStats(),
					},
					err: err,
				}
			}
		}(i)
	}

	// wait for shards to arrive on shardChan and assemble them into chunks
	rsc := m.ErasureCode()
	for remaining > 0 {
		var r shardRes
		select {
		case r = <-shardChan:
		case <-op.cancel:
			op.die(ErrCanceled)
		}
		// update chunk
		workMu.Lock()
		c := &chunks[r.chunk]
		if r.err != nil {
			c.status[r.shard] = shardMissing
			c.errs = append(c.errs, r.err.Error())
		} else {
			c.status[r.shard] = shardFinished
			var n int
			for _, s := range c.status {
				if s == shardFinished {
					n++
				}
			}
			c.done = n >= m.MinShards
		}
		workMu.Unlock()

		// if able, assemble chunk and write to file
		if r.err == nil {
			op.sendUpdate(r.stats)
			transferred += c.chunkSize / int64(m.MinShards)
			if transferred > m.Filesize {
				transferred = m.Filesize
			}
			op.sendUpdate(TransferProgressUpdate{
				Total:       m.Filesize,
				Start:       initialBytes,
				Transferred: transferred,
			})
			if c.done {
				// reconstruct missing data shards and write to file
				if _, err := f.Seek(c.fileOffset, io.SeekStart); err != nil {
					op.die(errors.Wrap(err, "could not seek within file"))
					return
				}
				err := rsc.Recover(f, c.shards, int(c.chunkSize))
				if err != nil {
					op.die(err)
					return
				}
				remaining -= c.chunkSize

				// give shard buffers to the next chunk and wake up any getWork
				// calls waiting for memory
				workMu.Lock()
				for i := range chunks {
					c2 := &chunks[i]
					if !c2.done && c2.shards == nil {
						c2.shards = c.shards
						for j := range c2.shards {
							c2.shards[j] = c2.shards[j][:0]
						}
						c.shards = nil
						chunkCond.Broadcast()
						break
					}
				}
				workMu.Unlock()
			}
		} else {
			// otherwise, check whether chunk is still recoverable
			if len(c.shards)-len(c.errs) < m.MinShards {
				err := errors.New("too many hosts did not supply their shard:\n" + strings.Join(c.errs, "\n"))
				op.die(err)
				return
			}
		}
	}
	op.die(nil)
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
