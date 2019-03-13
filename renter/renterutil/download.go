package renterutil

import (
	"hash/crc32"
	"io"
	"os"
	"strings"
	"sync"

	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renterhost"

	"github.com/pkg/errors"
)

// verifyFileContents checks whether the contents of f match the data of the
// metafile, returning the earliest offset at which the contents differ.
func verifyFileContents(m *renter.MetaFile, f io.Reader) (offset int64, err error) {
	// To determine the size of each chunk, we need the sector slices of the
	// Shards. We can assume that the size of each slice is the same across
	// each Shard.
	slices := make([][]renter.SectorSlice, m.MinShards)
	for i := range slices {
		shard, err := renter.ReadShard(m.ShardPath(m.Hosts[i]))
		if err != nil {
			return 0, errors.Wrap(err, "could not read shard")
		}
		slices[i] = shard
	}

	// Before verifying the checksums, we have to recreate the erasure-
	// encoding of the file. Since we're only looking at the data pieces,
	// we can use an m-of-m code.
	rsc := renter.NewRSCode(m.MinShards, m.MinShards)
	chunk := make([]byte, 0, renterhost.SectorSize*m.MinShards)
	dataShards := make([][]byte, m.MinShards)
	for i := range dataShards {
		dataShards[i] = make([]byte, 0, renterhost.SectorSize)
	}
	for chunkIndex := range slices[0] {
		chunkSize := int64(slices[0][chunkIndex].NumSegments) * merkle.SegmentSize * int64(m.MinShards)
		if offset+chunkSize > m.Filesize {
			chunkSize = m.Filesize - offset
		}
		buf := chunk[:chunkSize]
		_, err := io.ReadFull(f, buf)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				err = nil // benign
			}
			return offset, err
		}
		rsc.Encode(buf, dataShards)
		chunkOk := true
		for i, shard := range dataShards {
			chunkOk = chunkOk && (crc32.ChecksumIEEE(shard) == slices[i][chunkIndex].Checksum)
		}
		if !chunkOk {
			break
		}
		offset += chunkSize
	}
	return offset, nil
}

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
		if stat.Size() > m.Filesize {
			if err := f.Truncate(m.Filesize); err != nil {
				op.die(errors.Wrap(err, "could not resize file"))
				return
			}
		}
	}

	offset, err := verifyFileContents(m, f)
	if err != nil {
		op.die(errors.Wrap(err, "could not verify file contents"))
		return
	} else if offset == m.Filesize {
		// file is already fully downloaded
		op.die(nil)
		return
	}

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		op.die(err)
		return
	}
	downloadStream(op, f, offset, contracts, m, hkr)
}

// DownloadStream writes the contents of m to w.
func DownloadStream(w io.Writer, contracts renter.ContractSet, m *renter.MetaFile, hkr renter.HostKeyResolver) *Operation {
	op := newOperation()
	go downloadStream(op, w, 0, contracts, m, hkr)
	return op
}

type opWriter struct {
	w  io.Writer
	op *Operation
	up TransferProgressUpdate
}

func (w *opWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.up.Transferred += int64(n)
	w.op.sendUpdate(w.up)
	return n, err
}

func downloadStream(op *Operation, w io.Writer, offset int64, contracts renter.ContractSet, m *renter.MetaFile, hkr renter.HostKeyResolver) {
	downloaders, err := NewDownloaderSet(contracts, hkr)
	if err != nil {
		op.die(err)
		return
	}
	pf, err := NewPseudoFile(m, downloaders)
	if err != nil {
		op.die(err)
		return
	}

	// send initial progress
	up := TransferProgressUpdate{
		Total:       m.Filesize,
		Start:       offset,
		Transferred: 0,
	}
	op.sendUpdate(up)
	// monitor progress during download
	w = &opWriter{w, op, up}

	// seek to offset and begin transferring
	if _, err := pf.Seek(offset, io.SeekStart); err != nil {
		op.die(err)
		return
	}
	buf := make([]byte, m.MaxChunkSize()) // larger buffer means fewer updates
	if _, err := io.CopyBuffer(w, pf, buf); err != nil {
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

type lockedDownloader struct {
	d  *proto.Session
	mu *sync.Mutex
}

// A DownloaderSet groups a set of proto.Downloaders.
type DownloaderSet struct {
	downloaders map[hostdb.HostPublicKey]lockedDownloader
}

// Close closes all of the Downloaders in the set.
func (set *DownloaderSet) Close() error {
	for _, ld := range set.downloaders {
		ld.mu.Lock()
		ld.d.Close()
	}
	return nil
}

func (set *DownloaderSet) acquire(host hostdb.HostPublicKey) (*proto.Session, bool) {
	ld, ok := set.downloaders[host]
	if !ok {
		return nil, false
	}
	ld.mu.Lock()
	return ld.d, true
}

func (set *DownloaderSet) release(host hostdb.HostPublicKey) {
	set.downloaders[host].mu.Unlock()
}

// NewDownloaderSet creates a DownloaderSet composed of one proto.Downloader
// per contract.
func NewDownloaderSet(contracts renter.ContractSet, hkr renter.HostKeyResolver) (*DownloaderSet, error) {
	ds := &DownloaderSet{
		downloaders: make(map[hostdb.HostPublicKey]lockedDownloader),
	}
	for hostKey, contract := range contracts {
		hostIP, err := hkr.ResolveHostKey(contract.HostKey())
		if err != nil {
			// TODO: skip instead?
			return nil, errors.Wrapf(err, "%v: could not resolve host key", hostKey.ShortKey())
		}
		d, err := proto.NewSession(hostIP, contract, 0)
		if err != nil {
			// TODO: skip instead?
			return nil, err
		}
		ds.downloaders[hostKey] = lockedDownloader{d: d, mu: new(sync.Mutex)}
	}
	return ds, nil
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
