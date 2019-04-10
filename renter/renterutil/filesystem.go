package renterutil

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renterhost"
)

// helper type that skips a prefix of the bytes written to it; see
// (roPseudoFile).Read
type skipWriter struct {
	buf  []byte
	skip int
}

func (sw *skipWriter) Write(p []byte) (int, error) {
	toSkip := sw.skip
	if toSkip > len(p) {
		toSkip = len(p)
	}
	if len(p[toSkip:]) > len(sw.buf) {
		panic("write is too large for buffer")
	}
	n := copy(sw.buf, p[toSkip:])
	sw.buf = sw.buf[n:]
	sw.skip -= toSkip
	return len(p), nil
}

// helper type to implement os.FileInfo for metafiles
type pseudoFileInfo struct {
	name string
	m    renter.MetaIndex
}

func (i pseudoFileInfo) Name() string       { return i.name }
func (i pseudoFileInfo) Size() int64        { return i.m.Filesize }
func (i pseudoFileInfo) Mode() os.FileMode  { return i.m.Mode }
func (i pseudoFileInfo) ModTime() time.Time { return i.m.ModTime }
func (i pseudoFileInfo) IsDir() bool        { return false }
func (i pseudoFileInfo) Sys() interface{}   { return i.m }

// PseudoFS implements a filesystem by downloading data from Sia hosts.
type PseudoFS struct {
	root        string
	downloaders *DownloaderSet
}

func (fs *PseudoFS) path(name string) string {
	return filepath.Join(fs.root, name)
}

func isDir(path string) bool {
	stat, err := os.Stat(path)
	return err == nil && stat.IsDir()
}

// Chmod changes the mode of the named file to mode.
func (fs *PseudoFS) Chmod(name string, mode os.FileMode) error {
	path := fs.path(name)
	if isDir(path) {
		return os.Chmod(path, mode)
	}
	path += ".usa"
	// TODO: how does this interact with open files?
	// TODO: this can be done without a working directory
	m, err := renter.OpenMetaFile(path)
	if err != nil {
		return errors.Wrapf(err, "chmod %v", path)
	}
	m.Mode = mode
	if err := m.Close(); err != nil {
		return errors.Wrapf(err, "chmod %v", path)
	}
	return nil
}

// Create creates the named file with the specified redundancy and mode 0666
// (before umask), truncating it if it already exists. The returned file only
// supports Write calls at the end of the file.
func (fs *PseudoFS) Create(name string, minShards int) (PseudoFile, error) {
	return fs.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_TRUNC, 0666, minShards)
}

// Mkdir creates a new directory with the specified name and permission bits
// (before umask).
func (fs *PseudoFS) Mkdir(name string, perm os.FileMode) error {
	return os.Mkdir(fs.path(name), perm)
}

// MkdirAll creates a directory named path, along with any necessary parents,
// and returns nil, or else returns an error. The permission bits perm (before
// umask) are used for all directories that MkdirAll creates. If path is already
// a directory, MkdirAll does nothing and returns nil.
func (fs *PseudoFS) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(fs.path(path), perm)
}

// Open opens the named file for reading. The returned file is read-only.
func (fs *PseudoFS) Open(name string) (PseudoFile, error) {
	return fs.OpenFile(name, os.O_RDONLY, 0, 0)
}

// OpenFile is the generalized open call; most users will use Open or Create
// instead. It opens the named file with specified flag (os.O_RDONLY etc.) and perm
// (before umask), if applicable.
func (fs *PseudoFS) OpenFile(name string, flag int, perm os.FileMode, minShards int) (PseudoFile, error) {
	path := fs.path(name)
	if isDir(path) {
		dir, err := os.OpenFile(path, flag, perm)
		return &dirPseudoFile{dir}, err
	}
	path += ".usa"

	// currently, the only modes supported are RDONLY and APPEND
	if flag == os.O_RDONLY {
		index, shards, err := renter.ReadMetaFileContents(path)
		if err != nil {
			return nil, errors.Wrapf(err, "open %v", name)
		}
		return &roPseudoFile{
			pseudoFileInfo: pseudoFileInfo{name, index},
			shards:         shards,
			ds:             fs.downloaders,
			shardBufs:      make([]bytes.Buffer, len(shards)),
		}, nil
	} else if flag == os.O_APPEND|os.O_CREATE|os.O_TRUNC {
		// NewMetaFile expects a map of contracts, so fake one.
		// TODO: find a better way.
		contracts := make(renter.ContractSet)
		for hostKey := range fs.downloaders.downloaders {
			contracts[hostKey] = nil
		}
		m, err := renter.NewMetaFile(path, perm, 0, contracts, minShards)
		if err != nil {
			return nil, errors.Wrapf(err, "open %v", name)
		}
		shards := make([]*renter.Shard, len(m.Hosts))
		for i := range shards {
			sf, err := renter.OpenShard(m.ShardPath(m.Hosts[i]))
			if err != nil {
				return nil, errors.Wrapf(err, "open %v", name)
			}
			shards[i] = sf
		}
		return &aoPseudoFile{
			pseudoFileInfo: pseudoFileInfo{name, m.MetaIndex},
			m:              m,
			shards:         shards,
			ds:             fs.downloaders,
		}, nil
	} else {
		return nil, errors.New("unsupported flag combination")
	}
}

// Remove removes the named file or (empty) directory.
func (fs *PseudoFS) Remove(name string) error {
	path := fs.path(name)
	if !isDir(path) {
		path += ".usa"
	}
	// TODO: delete remote sectors?
	// TODO: how does this interact with open files?
	return os.Remove(path)
}

// RemoveAll removes path and any children it contains. It removes everything it
// can but returns the first error it encounters. If the path does not exist,
// RemoveAll returns nil (no error).
func (fs *PseudoFS) RemoveAll(path string) error {
	// TODO: delete remote sectors?
	// TODO: how does this interact with open files?
	path = fs.path(path)
	if !isDir(path) {
		path += ".usa"
	}
	return os.RemoveAll(path)
}

// Rename renames (moves) oldpath to newpath. If newpath already exists and is
// not a directory, Rename replaces it. OS-specific restrictions may apply when
// oldpath and newpath are in different directories.
func (fs *PseudoFS) Rename(oldname, newname string) error {
	// TODO: how does this interact with open files?
	oldpath, newpath := fs.path(oldname), fs.path(newname)
	if !isDir(oldpath) {
		oldpath += ".usa"
	}
	if !isDir(newpath) {
		newpath += ".usa"
	}
	return os.Rename(oldpath, newpath)
}

// Stat returns the FileInfo structure describing file.
func (fs *PseudoFS) Stat(name string) (os.FileInfo, error) {
	path := fs.path(name)
	if isDir(path) {
		return os.Stat(path)
	}
	path += ".usa"
	index, err := renter.ReadMetaIndex(path)
	if err != nil {
		return nil, errors.Wrapf(err, "stat %v", name)
	}
	return pseudoFileInfo{name, index}, nil
}

// Close closes the filesystem by terminating all active host sessions.
func (fs *PseudoFS) Close() error {
	return fs.downloaders.Close()
}

// NewFileSystem returns a new pseudo-filesystem rooted at root, which must be a
// directory containing only metafiles and other directories.
func NewFileSystem(root string, contracts renter.ContractSet, hkr renter.HostKeyResolver) (*PseudoFS, error) {
	ds, err := NewDownloaderSet(contracts, hkr)
	if err != nil {
		return nil, err
	}
	return &PseudoFS{
		root:        root,
		downloaders: ds,
	}, nil
}

// A PseudoFile presents a file-like interface for a metafile stored on Sia
// hosts.
type PseudoFile interface {
	Close() error
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	ReadAt(p []byte, off int64) (int, error)
	WriteAt(p []byte, off int64) (int, error)
	Seek(offset int64, whence int) (int64, error)
	Name() string
	Readdir(n int) ([]os.FileInfo, error)
	Readdirnames(n int) ([]string, error)
	Stat() (os.FileInfo, error)
	Sync() error
	Truncate(size int64) error
}

// A dirPseudoFile is a wrapper around a directory file, overloading only the
// Readdir method to operate on metafiles instead of standard files.
type dirPseudoFile struct {
	*os.File
}

func (f *dirPseudoFile) Readdir(n int) ([]os.FileInfo, error) {
	files, err := f.File.Readdir(n)
	for i := range files {
		if files[i].IsDir() {
			continue
		}
		index, err := renter.ReadMetaIndex(filepath.Join(f.File.Name(), files[i].Name()))
		if err != nil {
			return nil, err
		}
		files[i] = pseudoFileInfo{
			m:    index,
			name: strings.TrimSuffix(files[i].Name(), ".usa"),
		}
	}
	return files, err
}

// An roPseudoFile is a read-only PseudoFile.
type roPseudoFile struct {
	pseudoFileInfo
	perm      int
	shards    [][]renter.SectorSlice
	ds        *DownloaderSet
	offset    int64
	shardBufs []bytes.Buffer
	mu        sync.Mutex // serializes all methods
}

var errNoHost = errors.New("no downloader for this host")

func (f *roPseudoFile) downloadShards(offset int64, n int) ([][]byte, error) {
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
	start := (offset / int64(f.m.MinShards*merkle.SegmentSize)) * merkle.SegmentSize
	end := ((offset + int64(n)) / int64(f.m.MinShards*merkle.SegmentSize)) * merkle.SegmentSize
	if (offset+int64(n))%int64(f.m.MinShards*merkle.SegmentSize) != 0 {
		end += merkle.SegmentSize
	}
	offset, length := start, end-start

	// download in parallel
	type result struct {
		shardIndex int
		shard      []byte
		err        error
	}
	reqChan := make(chan int, f.m.MinShards)
	resChan := make(chan result, f.m.MinShards)
	var wg sync.WaitGroup
	reqIndex := 0
	for ; reqIndex < f.m.MinShards; reqIndex++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for shardIndex := range reqChan {
				res := result{shardIndex: shardIndex}
				host := hosts[shardIndex]
				if host == nil {
					res.err = errNoHost
				} else {
					buf := &f.shardBufs[shardIndex]
					buf.Reset()
					res.err = host.CopySection(buf, offset, length)
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
	for len(goodRes) < f.m.MinShards && len(badRes) <= len(hosts)-f.m.MinShards {
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
	if len(goodRes) < f.m.MinShards {
		var errStrings []string
		for _, r := range badRes {
			if r.err != errNoHost {
				errStrings = append(errStrings, r.err.Error())
			}
		}
		return nil, errors.New("too many hosts did not supply their shard:\n" + strings.Join(errStrings, "\n"))
	}
	shards := make([][]byte, len(hosts))
	for _, r := range goodRes {
		shards[r.shardIndex] = r.shard
	}
	return shards, nil
}

// Read reads up to len(p) bytes from the File. It returns the number of bytes
// read and any error encountered.
func (f *roPseudoFile) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.offset >= f.m.Filesize {
		return 0, io.EOF
	} else if int64(len(p)) > f.m.Filesize-f.offset {
		// partial read
		p = p[:f.m.Filesize-f.offset]
	}

	shards, err := f.downloadShards(f.offset, len(p))
	if err != nil {
		return 0, err
	}

	// recover data shards directly into p
	skip := int(f.offset % (int64(f.m.MinShards) * merkle.SegmentSize))
	w := &skipWriter{p, skip}
	err = f.m.ErasureCode().Recover(w, shards, skip+len(p))
	if err != nil {
		return 0, errors.Wrap(err, "could not recover chunk")
	}
	f.offset += int64(len(p))
	return len(p), nil
}

// ReadAt reads len(p) bytes from the File starting at byte offset off. It
// returns the number of bytes read and the error, if any. ReadAt always returns
// a non-nil error when n < len(p). At end of file, that error is io.EOF.
func (f *roPseudoFile) ReadAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	partial := false
	if off >= f.m.Filesize {
		return 0, io.EOF
	} else if off+int64(len(p)) > f.m.Filesize {
		p = p[:f.m.Filesize-off]
		partial = true
	}

	shards, err := f.downloadShards(off, len(p))
	if err != nil {
		return 0, err
	}

	// recover data shards directly into p
	skip := int(off % merkle.SegmentSize)
	w := &skipWriter{p, skip}
	err = f.m.ErasureCode().Recover(w, shards, skip+len(p))
	if err != nil {
		return 0, errors.Wrap(err, "could not recover chunk")
	}
	if partial {
		return len(p), io.EOF
	}
	return len(p), nil
}

// Seek sets the offset for the next Read or Write on file to offset,
// interpreted according to whence. It returns the new offset and an error, if
// any. If f was opened with O_APPEND, Seek always returns an error.
func (f *roPseudoFile) Seek(offset int64, whence int) (int64, error) {
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

// Name returns the name of the file.
func (f *roPseudoFile) Name() string {
	return f.name
}

// Stat returns the FileInfo structure describing f.
func (f *roPseudoFile) Stat() (os.FileInfo, error) {
	return f.pseudoFileInfo, nil
}

// Close closes the file, rendering it unusable for I/O.
func (f *roPseudoFile) Close() error {
	return nil
}

// Sync commits the current contents of the file to its Sia hosts.
func (f *roPseudoFile) Sync() error {
	return nil
}

func (f *roPseudoFile) Write(p []byte) (int, error) {
	return 0, errors.New("file is read-only")
}

func (f *roPseudoFile) WriteAt(p []byte, off int64) (int, error) {
	return 0, errors.New("file is read-only")
}

func (f *roPseudoFile) Readdir(n int) ([]os.FileInfo, error) {
	return nil, errors.New("not a directory")
}

func (f *roPseudoFile) Readdirnames(n int) ([]string, error) {
	return nil, errors.New("not a directory")
}

func (f *roPseudoFile) Truncate(size int64) error {
	return errors.New("file is read-only")
}

// An aoPseudoFile is a PseudoFile in O_APPEND mode, supporting only writes at
// the end of the file.
type aoPseudoFile struct {
	pseudoFileInfo
	m          *renter.MetaFile
	ds         *DownloaderSet
	shards     []*renter.Shard
	chunkIndex int64
	mu         sync.Mutex
}

// Write writes len(p) bytes to the File. It returns the number of bytes written
// and an error, if any. Write returns a non-nil error when n != len(p).
func (f *aoPseudoFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	rsc := f.m.ErasureCode()
	shards := make([][]byte, len(f.m.Hosts))
	for i := range shards {
		shards[i] = make([]byte, renterhost.SectorSize)
	}
	// encode p into shards
	rsc.Encode(p, shards)

	// acquire uploaders
	hosts := make([]*renter.ShardUploader, len(f.m.Hosts))
	for i, hostKey := range f.m.Hosts {
		d, ok := f.ds.acquire(hostKey)
		if !ok {
			continue
		}
		defer f.ds.release(hostKey)
		hosts[i] = &renter.ShardUploader{
			Uploader: d,
			Shard:    f.shards[i],
			Key:      f.m.MasterKey,
		}
	}

	// upload each shard
	for i := range shards {
		_, err := hosts[i].EncryptAndUpload(shards[i], f.chunkIndex)
		if err != nil {
			return 0, err
		}
	}
	f.chunkIndex++
	f.m.Filesize += int64(len(p))
	return len(p), nil
}

func (f *aoPseudoFile) WriteAt(p []byte, off int64) (int, error) {
	// TODO: technically we could support WriteAt when off == filesize, but no
	// point bothering yet. We'll come back to it when arbitrary writes are
	// supported.
	return 0, errors.New("file is append-only")
}

func (f *aoPseudoFile) Seek(offset int64, whence int) (int64, error) {
	// TODO: technically we could support Seek, as long as the seek offset is at
	// the end of the file when Write is called, but no point bothering yet.
	// We'll come back to it when arbitrary writes are supported.
	return 0, errors.New("file is append-only")
}

// Name returns the name of the file.
func (f *aoPseudoFile) Name() string {
	return f.name
}

// Stat returns the FileInfo structure describing f.
func (f *aoPseudoFile) Stat() (os.FileInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pseudoFileInfo, nil
}

// Sync commits the current contents of the file to its Sia hosts.
func (f *aoPseudoFile) Sync() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	panic("unimplemented")
}

// Truncate changes the size of the file. It does not change the I/O offset.
// The new size may not be greater than the current size.
func (f *aoPseudoFile) Truncate(size int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if size < 0 {
		return errors.New("new size cannot be negative")
	}
	if size > f.m.Filesize {
		return errors.New("new size cannot exceed current size")
	}
	f.m.Filesize = size
	return nil
}

// Close closes the file, rendering it unusable for I/O.
func (f *aoPseudoFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.m.Close()
}

func (f *aoPseudoFile) Read(p []byte) (int, error) {
	return 0, errors.New("file is append-only")
}

func (f *aoPseudoFile) ReadAt(p []byte, off int64) (int, error) {
	return 0, errors.New("file is append-only")
}

func (f *aoPseudoFile) Readdir(n int) ([]os.FileInfo, error) {
	return nil, errors.New("not a directory")
}

func (f *aoPseudoFile) Readdirnames(n int) ([]string, error) {
	return nil, errors.New("not a directory")
}
