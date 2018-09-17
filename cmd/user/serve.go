package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renter/renterutil"
	"lukechampine.com/us/renterhost"
)

func serve(contractDir, metaDir, addr string) error {
	contracts, err := loadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer contracts.Close()

	c := makeClient()
	downloaders, err := newDownloaderSet(contracts, c.Scan)
	if err != nil {
		return errors.Wrap(err, "could not connect to hosts")
	}

	srv := &http.Server{
		Addr:    addr,
		Handler: http.FileServer(httpDir(metaDir, downloaders)),
	}
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt)
		<-sigChan
		log.Println("Stopping server...")
		srv.Close()
	}()
	log.Printf("Listening on %v...", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// A downloaderSet groups a set of proto.Downloaders.
type downloaderSet struct {
	downloaders map[hostdb.HostPublicKey]*proto.Downloader
	mu          sync.Mutex
}

// Close closes all of the Downloaders in the set.
func (set *downloaderSet) Close() error {
	for _, d := range set.downloaders {
		d.Close()
	}
	return nil
}

func (set *downloaderSet) downloadChunkShards(m renter.MetaIndex, shards [][]renter.SectorSlice, chunkIndex int64) ([][]byte, int, error) {
	set.mu.Lock()
	defer set.mu.Unlock()
	hosts := make([]*renter.ShardDownloader, len(m.Hosts))
	for i, hostKey := range m.Hosts {
		d, ok := set.downloaders[hostKey]
		if !ok {
			continue
		}
		hosts[i] = &renter.ShardDownloader{
			Downloader: d,
			Key:        m.EncryptionKey(i),
			Slices:     shards[i],
		}
	}
	chunkShards, shardLen, _, err := renterutil.DownloadChunkShards(hosts, chunkIndex, m.MinShards, nil)
	if err != nil {
		return nil, 0, err
	}
	// copy shard data to prevent a race
	shardsCopy := make([][]byte, len(chunkShards))
	for i := range shardsCopy {
		shardsCopy[i] = append([]byte(nil), chunkShards[i]...)
	}
	return shardsCopy, shardLen, nil
}

// newDownloaderSet creates a downloaderSet composed of one proto.Downloader
// per contract.
func newDownloaderSet(contracts renter.ContractSet, scan renter.ScanFn) (*downloaderSet, error) {
	ds := &downloaderSet{
		downloaders: make(map[hostdb.HostPublicKey]*proto.Downloader),
	}
	for hostKey, contract := range contracts {
		host, err := scan(contract.HostKey())
		if err != nil {
			// TODO: skip instead?
			return nil, errors.Wrapf(err, "%v: could not scan host", hostKey.ShortKey())
		}
		d, err := proto.NewDownloader(host, contract)
		if err != nil {
			// TODO: skip instead?
			return nil, err
		}
		ds.downloaders[hostKey] = d
	}
	return ds, nil
}

// A httpFile implements the http.File interface by downloading data from
// Sia hosts.
type httpFile struct {
	m    renter.MetaIndex
	path string

	mu sync.Mutex
	dr *downloadReader
}

func (f *httpFile) Close() error                       { return nil }
func (f *httpFile) Readdir(int) ([]os.FileInfo, error) { return nil, nil }
func (f *httpFile) Stat() (os.FileInfo, error)         { return f, nil }
func (f *httpFile) Name() string                       { return strings.TrimSuffix(f.path, metafileExt) }
func (f *httpFile) Size() int64                        { return f.m.Filesize }
func (f *httpFile) Mode() os.FileMode                  { return f.m.Mode }
func (f *httpFile) ModTime() time.Time                 { return f.m.ModTime }
func (f *httpFile) IsDir() bool                        { return false }
func (f *httpFile) Sys() interface{}                   { return nil }

// Read implements io.Reader.
func (f *httpFile) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dr.Read(p)
}

// Seek implements io.Seeker.
func (f *httpFile) Seek(offset int64, whence int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dr.Seek(offset, whence)
}

// HTTPFile returns an http.File for the specified metafile.
func HTTPFile(name string, downloaders *downloaderSet) (http.File, error) {
	index, shards, err := renter.ReadMetaFileContents(name)
	if err != nil {
		return nil, errors.Wrap(err, "could not extract meta file")
	}
	if len(shards) == 0 {
		return nil, errors.New("empty file")
	}

	dr, err := newDownloadReader(index, shards, downloaders)
	if err != nil {
		return nil, errors.Wrap(err, "could not connect to hosts")
	}

	return &httpFile{
		m:    index,
		path: name,
		dr:   dr,
	}, nil
}

type httpFS struct {
	root        string
	downloaders *downloaderSet
}

func (fs *httpFS) Open(name string) (http.File, error) {
	name = filepath.Join(fs.root, name)
	stat, err := os.Stat(name)
	if err != nil {
		return nil, errors.Wrap(err, "could not stat file")
	} else if stat.IsDir() {
		return os.Open(name)
	}
	return HTTPFile(name, fs.downloaders)
}

// httpDir returns an object that implements http.FileSystem for the given
// meta file root directory.
func httpDir(root string, downloaders *downloaderSet) http.FileSystem {
	return &httpFS{
		root:        root,
		downloaders: downloaders,
	}
}

type downloadReader struct {
	m      renter.MetaIndex
	shards [][]renter.SectorSlice
	ds     *downloaderSet

	buf           chunkBuffer
	chunk         int64 // current chunk index
	offset        int64 // current offset within file
	lastChunkSize int64
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
	if newOffset < 0 || newOffset > dr.m.Filesize {
		return 0, errors.New("seek position is out of bounds")
	}

	newChunk, chunkOffset := dr.chunkOffset(offset)
	if newChunk != dr.chunk {
		err := dr.downloadChunk(newChunk)
		if err != nil {
			return 0, err
		}
		dr.chunk = newChunk
	}
	if _, err := dr.buf.Seek(chunkOffset, io.SeekStart); err != nil {
		return 0, io.EOF
	}
	dr.offset = newOffset
	return dr.offset, nil
}

func (dr *downloadReader) Read(p []byte) (total int, err error) {
	for total < len(p) {
		var n int
		n, err = dr.buf.Read(p[total:])
		total += n
		if err == io.EOF {
			nextChunk := dr.chunk + 1
			err = dr.downloadChunk(nextChunk)
			if err != nil {
				break
			}
			dr.chunk = nextChunk
			dr.buf.Seek(0, io.SeekStart)
		}
	}
	return total, err
}

func (dr *downloadReader) downloadChunk(chunk int64) error {
	if chunk >= int64(len(dr.shards[0])) {
		return io.EOF
	}
	shards, shardLen, err := dr.ds.downloadChunkShards(dr.m, dr.shards, chunk)
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

func (dr *downloadReader) chunkOffset(offset int64) (chunkIndex, chunkOffset int64) {
	if len(dr.shards) == 0 {
		return -1, -1
	}
	rem := offset
	for i, s := range dr.shards[0] {
		chunkSize := int64(s.Length) * int64(dr.m.MinShards)
		if rem < chunkSize {
			return int64(i), rem
		}
		rem -= chunkSize
	}
	return -1, -1
}

func newDownloadReader(m renter.MetaIndex, shards [][]renter.SectorSlice, ds *downloaderSet) (*downloadReader, error) {
	// determine lastChunkSize
	lastChunkSize := m.Filesize
	for _, s := range shards[0][:len(shards[0])-1] {
		lastChunkSize -= int64(s.Length) * int64(m.MinShards)
	}
	return &downloadReader{
		m:      m,
		shards: shards,
		ds:     ds,
		buf: chunkBuffer{
			buf: make([]byte, 0, renterhost.SectorSize*m.MinShards),
		},
		chunk:         -1,
		lastChunkSize: lastChunkSize,
	}, nil
}

type chunkBuffer struct {
	buf []byte
	off int
}

func (b *chunkBuffer) Reset() {
	b.off = 0
	b.buf = b.buf[:0]
}

func (b *chunkBuffer) Read(p []byte) (n int, err error) {
	if b.off >= len(b.buf) {
		if len(p) == 0 {
			return 0, nil
		}
		return 0, io.EOF
	}
	n = copy(p, b.buf[b.off:])
	b.off += n
	return
}

func (b *chunkBuffer) Write(p []byte) (n int, err error) {
	b.buf = b.buf[:b.off+len(p)]
	n = copy(b.buf[b.off:], p)
	b.off += n
	return
}

func (b *chunkBuffer) Seek(offset int64, whence int) (int64, error) {
	var newOffset int
	switch whence {
	case io.SeekStart:
		newOffset = int(offset)
	case io.SeekCurrent:
		newOffset = b.off + int(offset)
	case io.SeekEnd:
		newOffset = len(b.buf) - int(offset)
	}
	if newOffset < 0 || newOffset > len(b.buf) {
		return 0, errors.New("invalid offset")
	}
	b.off = newOffset
	return int64(b.off), nil
}
