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
	"gitlab.com/NebulousLabs/Sia/types"
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
	root  string
	hosts *HostSet
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
	path += metafileExt
	// TODO: how does this interact with open files?
	// TODO: this can be done without a working directory
	m, err := renter.OpenMetaFile(path)
	if err != nil {
		return errors.Wrapf(err, "chmod %v", path)
	}
	m.Mode = mode
	m.ModTime = time.Now()
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
	path += metafileExt

	// currently, the only modes supported are RDONLY and APPEND
	if flag == os.O_RDONLY {
		index, shards, err := renter.ReadMetaFileContents(path)
		if err != nil {
			return nil, errors.Wrapf(err, "open %v", name)
		}
		return &roPseudoFile{
			pseudoFileInfo: pseudoFileInfo{name, index},
			shards:         shards,
			hs:             fs.hosts,
			shardBufs:      make([]bytes.Buffer, len(shards)),
		}, nil
	} else if flag&os.O_APPEND != 0 {
		var m *renter.MetaFile
		var err error
		if flag == os.O_APPEND|os.O_CREATE|os.O_TRUNC {
			// NewMetaFile expects a map of contracts, so fake one.
			// TODO: find a better way.
			contracts := make(renter.ContractSet)
			for hostKey := range fs.hosts.sessions {
				contracts[hostKey] = nil
			}
			m, err = renter.NewMetaFile(path, perm, 0, contracts, minShards)
		} else if flag == os.O_APPEND {
			m, err = renter.OpenMetaFile(path)
		} else {
			return nil, errors.New("unsupported flag combination")
		}
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
		// determine chunkIndex
		slices, err := renter.ReadShard(m.ShardPath(m.Hosts[0]))
		if err != nil {
			return nil, errors.Wrapf(err, "open %v", name)
		}
		chunkIndex := int64(len(slices))
		return &aoPseudoFile{
			pseudoFileInfo: pseudoFileInfo{name, m.MetaIndex},
			m:              m,
			shards:         shards,
			hs:             fs.hosts,
			chunkIndex:     chunkIndex,
		}, nil
	} else {
		return nil, errors.New("unsupported flag combination")
	}
}

// Remove removes the named file or (empty) directory.
func (fs *PseudoFS) Remove(name string) error {
	path := fs.path(name)
	if !isDir(path) {
		path += metafileExt
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
		path += metafileExt
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
		oldpath += metafileExt
	}
	if !isDir(newpath) {
		newpath += metafileExt
	}
	return os.Rename(oldpath, newpath)
}

// Stat returns the FileInfo structure describing file.
func (fs *PseudoFS) Stat(name string) (os.FileInfo, error) {
	path := fs.path(name)
	if isDir(path) {
		return os.Stat(path)
	}
	path += metafileExt
	index, err := renter.ReadMetaIndex(path)
	if err != nil {
		return nil, errors.Wrapf(err, "stat %v", name)
	}
	return pseudoFileInfo{name, index}, nil
}

// Close closes the filesystem by terminating all active host sessions.
func (fs *PseudoFS) Close() error {
	return fs.hosts.Close()
}

// NewFileSystem returns a new pseudo-filesystem rooted at root, which must be a
// directory containing only metafiles and other directories.
func NewFileSystem(root string, contracts renter.ContractSet, hkr renter.HostKeyResolver, currentHeight types.BlockHeight) *PseudoFS {
	return &PseudoFS{
		root:  root,
		hosts: NewHostSet(contracts, hkr, currentHeight),
	}
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
			name: strings.TrimSuffix(files[i].Name(), metafileExt),
		}
	}
	return files, err
}

// An roPseudoFile is a read-only PseudoFile.
type roPseudoFile struct {
	pseudoFileInfo
	shards    [][]renter.SectorSlice
	hs        *HostSet
	offset    int64
	shardBufs []bytes.Buffer
	mu        sync.Mutex // serializes all methods
}

func (f *roPseudoFile) downloadShards(offset int64, n int) ([][]byte, error) {
	hosts := make([]*renter.ShardDownloader, len(f.m.Hosts))
	hostErrs := make([]error, len(f.m.Hosts))
	for i, hostKey := range f.m.Hosts {
		s, err := f.hs.acquire(hostKey)
		if err != nil {
			hostErrs[i] = err
			continue
		}
		defer f.hs.release(hostKey)
		hosts[i] = &renter.ShardDownloader{
			Downloader: s,
			Key:        f.m.MasterKey,
			Slices:     f.shards[i],
		}
	}
	// compute per-shard offset + length, padding to segment size
	start := (offset / f.m.MinChunkSize()) * merkle.SegmentSize
	end := ((offset + int64(n)) / f.m.MinChunkSize()) * merkle.SegmentSize
	if (offset+int64(n))%f.m.MinChunkSize() != 0 {
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
					res.err = hostErrs[shardIndex]
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
	var shardLen int
	for _, r := range goodRes {
		shards[r.shardIndex] = r.shard
		shardLen = len(r.shard)
	}
	for i := range shards {
		if len(shards[i]) == 0 {
			shards[i] = make([]byte, 0, shardLen)
		}
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
	skip := int(f.offset % f.m.MinChunkSize())
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
	hs         *HostSet
	shards     []*renter.Shard
	chunk      []byte
	chunkIndex int64
	mu         sync.Mutex
}

func (f *aoPseudoFile) readChunkAt(p []byte, off int64) error {
	if int64(len(p))%f.m.MinChunkSize() != 0 {
		panic("illegal chunk size")
	}
	if off >= f.m.Filesize {
		return io.EOF
	}

	hosts := make([]*renter.ShardDownloader, len(f.m.Hosts))
	for i, hostKey := range f.m.Hosts {
		s, err := f.hs.acquire(hostKey)
		if err != nil {
			continue
		}
		defer f.hs.release(hostKey)
		slices, err := renter.ReadShard(f.m.ShardPath(hostKey))
		if err != nil {
			return err
		}
		hosts[i] = &renter.ShardDownloader{
			Downloader: s,
			Key:        f.m.MasterKey,
			Slices:     slices,
		}
	}
	start := (off / f.m.MinChunkSize()) * merkle.SegmentSize
	offset, length := start, int64(merkle.SegmentSize)

	shards := make([][]byte, len(hosts))
	var nShards int
	for shardIndex, host := range hosts {
		if host == nil {
			continue
		}
		var buf bytes.Buffer
		err := host.CopySection(&buf, offset, length)
		if err == nil {
			shards[shardIndex] = buf.Bytes()
			if nShards++; nShards >= f.m.MinShards {
				break
			}
		}
	}
	for i := range shards {
		if len(shards[i]) == 0 {
			shards[i] = make([]byte, 0, merkle.SegmentSize)
		}
	}

	// recover data shards directly into p
	w := &skipWriter{p, 0}
	err := f.m.ErasureCode().Recover(w, shards, len(p))
	if err != nil {
		return errors.Wrap(err, "could not recover chunk")
	}
	return nil
}

// uncommittedFilesize returns the size that f will be after the next call to
// flushChunk.
func (f *aoPseudoFile) uncommittedFilesize() int64 {
	size := f.m.Filesize
	if len(f.chunk) > 0 {
		align := f.m.Filesize % f.m.MinChunkSize()
		size += int64(len(f.chunk)) - align
	}
	return size
}

// flushChunk encodes the current (uncommitted) chunk, uploads the resulting
// shards to f's hosts, and updates f's Shard files, Filesize, and ModTime to
// reflect the change. flushChunk always uploads a full sector to each host, so
// it is wasteful to call it if the current chunk is not full.
func (f *aoPseudoFile) flushChunk() error {
	if len(f.chunk) == 0 {
		return nil
	}

	// if necessary, update previous SectorSlice
	align := int(f.m.Filesize % f.m.MinChunkSize())
	if align != 0 {
		// The current offset is unaligned, i.e. the previous write did not
		// occupy a full chunk, and was thus padded with zeros. We want to fill
		// those zeros with data from p, but we can't upload less than a chunk.
		// So we need to download the previous partial chunk, append p to it
		// (thus overwriting any zeros), and upload the result. We also need to
		// update the previous write's SectorSlice, or even delete it entirely.
		for i, hostKey := range f.m.Hosts {
			slices, err := renter.ReadShard(f.m.ShardPath(hostKey))
			if err != nil {
				return err
			}
			s := slices[len(slices)-1]
			s.NumSegments--
			if s.NumSegments == 0 {
				f.chunkIndex = int64(len(slices) - 1)
			} else {
				if err := f.shards[i].WriteSlice(s, int64(len(slices)-1)); err != nil {
					return err
				}
			}
		}
	}

	// acquire uploaders
	hosts := make([]*renter.ShardUploader, len(f.m.Hosts))
	for i, hostKey := range f.m.Hosts {
		s, err := f.hs.acquire(hostKey)
		if err != nil {
			return err
		}
		defer f.hs.release(hostKey)
		hosts[i] = &renter.ShardUploader{
			Uploader: s,
			Shard:    f.shards[i],
			Key:      f.m.MasterKey,
		}
	}

	// encode chunk into shards
	shards := make([][]byte, len(hosts))
	for i := range shards {
		shards[i] = make([]byte, renterhost.SectorSize)
	}
	f.m.ErasureCode().Encode(f.chunk, shards)

	// upload each shard
	for i := range hosts {
		if _, err := hosts[i].EncryptAndUpload(shards[i], f.chunkIndex); err != nil {
			return err
		}
	}

	// update metadata
	f.m.Filesize = f.uncommittedFilesize()
	f.m.ModTime = time.Now()
	// reset chunk
	f.chunk = f.chunk[:0]
	f.chunkIndex++
	return nil
}

// Write writes len(p) bytes to the File. It returns the number of bytes written
// and an error, if any. Write returns a non-nil error when n != len(p).
func (f *aoPseudoFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(p) > renterhost.SectorSize*f.m.MinShards {
		// TODO: handle large writes
		return 0, errors.New("cannot handle writes larger than chunk size")
	}

	// if the chunk is full, flush it to hosts before continuing
	//
	// TODO: fill remaining space, following heuristic from uploadDir
	if len(f.chunk)+len(p) > renterhost.SectorSize*f.m.MinShards {
		if err := f.flushChunk(); err != nil {
			return 0, err
		}
	}

	// if necessary, prefix chunk with previous segment data
	if align := int(f.m.Filesize % f.m.MinChunkSize()); align != 0 && len(f.chunk) == 0 {
		// The last segment in the file is padded with zeros. We can't overwrite
		// just those zeros; we have to overwrite at least a full segment. So we
		// have to download the old segment, overwrite the zeros, and reupload
		// it. We'll also need to subtract one segment from the last
		// SectorSlice, so that when we append our new SectorSlice, the new
		// segment will be used.
		chunk := make([]byte, f.m.MinChunkSize())
		err := f.readChunkAt(chunk[:f.m.MinChunkSize()], f.m.Filesize-int64(align))
		if err != nil {
			return 0, err
		}
		f.chunk = append(f.chunk, chunk[:align]...)
	}

	f.chunk = append(f.chunk, p...)
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
	info := f.pseudoFileInfo
	info.m.Filesize = f.uncommittedFilesize()
	return info, nil
}

// Sync commits the current contents of the file to its Sia hosts.
func (f *aoPseudoFile) Sync() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.flushChunk()
}

// Truncate changes the size of the file. It does not change the I/O offset.
// The new size may not be greater than the current size.
func (f *aoPseudoFile) Truncate(size int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if size < 0 {
		return errors.New("new size cannot be negative")
	}
	if size > f.uncommittedFilesize() {
		return errors.New("new size cannot exceed current size")
	} else if size >= f.m.Filesize {
		// we're only truncating uncommitted data
		f.chunk = f.chunk[:len(f.chunk)-int(f.uncommittedFilesize()-size)]
		return nil
	}

	f.chunk = f.chunk[:0]
	f.m.Filesize = size

	// update shard files
	for shardIndex, hostKey := range f.m.Hosts {
		slices, err := renter.ReadShard(f.m.ShardPath(hostKey))
		if err != nil {
			return err
		}
		var n int64
		for i, s := range slices {
			sliceSize := int64(s.NumSegments) * f.m.MinChunkSize()
			if n+sliceSize > f.m.Filesize {
				// trim number of segments
				s.NumSegments -= uint32(n+sliceSize-f.m.Filesize) / uint32(f.m.MinChunkSize())
				if s.NumSegments == 0 {
					slices = slices[:i]
				} else {
					if err := f.shards[shardIndex].WriteSlice(s, int64(i)); err != nil {
						return err
					}
					slices = slices[:i+1]
				}
				break
			}
			n += sliceSize
		}
		err = os.Truncate(f.m.ShardPath(hostKey), int64(len(slices))*renter.SectorSliceSize)
		if err != nil {
			return err
		}
	}

	f.m.ModTime = time.Now()
	return nil
}

// Close closes the file, rendering it unusable for I/O.
func (f *aoPseudoFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.flushChunk(); err != nil {
		return err
	}
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
