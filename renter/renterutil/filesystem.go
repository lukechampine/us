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
	"gitlab.com/NebulousLabs/Sia/crypto"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter"
)

// ErrInvalidFileDescriptor is returned when I/O is attempted on an unknown file
// descriptor.
var ErrInvalidFileDescriptor = errors.New("invalid file descriptor")

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

// PseudoFS implements a filesystem by uploading and downloading data from Sia
// hosts.
type PseudoFS struct {
	root           string
	curFD          int
	files          map[int]*openMetaFile
	dirs           map[int]*os.File
	hosts          *HostSet
	sectors        map[hostdb.HostPublicKey]*renter.SectorBuilder
	lastCommitTime time.Time
	mu             sync.RWMutex
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

	// check for open file
	for _, of := range fs.files {
		if of.name == name {
			of.m.Mode = mode
			of.m.ModTime = time.Now()
			return nil
		}
	}

	m, err := renter.ReadMetaFile(path)
	if err != nil {
		return errors.Wrapf(err, "chmod %v", path)
	}
	m.Mode = mode
	m.ModTime = time.Now()
	if err := renter.WriteMetaFile(path, m); err != nil {
		return errors.Wrapf(err, "chmod %v", path)
	}
	return nil
}

// Create creates the named file with the specified redundancy and mode 0666
// (before umask), truncating it if it already exists. The returned file has
// mode O_RDWR.
func (fs *PseudoFS) Create(name string, minShards int) (*PseudoFile, error) {
	return fs.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0666, minShards)
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
func (fs *PseudoFS) Open(name string) (*PseudoFile, error) {
	return fs.OpenFile(name, os.O_RDONLY, 0, 0)
}

// OpenFile is the generalized open call; most users will use Open or Create
// instead. It opens the named file with specified flag (os.O_RDONLY etc.) and perm
// (before umask), if applicable.
func (fs *PseudoFS) OpenFile(name string, flag int, perm os.FileMode, minShards int) (*PseudoFile, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	path := fs.path(name)
	if isDir(path) {
		dir, err := os.OpenFile(path, flag, perm)
		if err != nil {
			return nil, err
		}
		fs.dirs[fs.curFD] = dir
		fs.curFD++
		return &PseudoFile{
			name: name,
			fd:   fs.curFD - 1,
			fs:   fs,
		}, nil
	}
	path += metafileExt

	// first check open files
	//
	// TODO: handle more flag combos here
	for fd, of := range fs.files {
		if of.name == name {
			of.closed = false
			of.offset = 0
			if flag&os.O_APPEND == os.O_APPEND {
				of.offset = of.filesize()
			}
			return &PseudoFile{
				name:  name,
				flags: flag,
				fd:    fd,
				fs:    fs,
			}, nil
		}
	}

	// no open file; create/open a metafile on disk
	var m *renter.MetaFile
	if flag&os.O_CREATE == os.O_CREATE {
		if len(fs.hosts.sessions) < minShards {
			return nil, errors.New("minShards cannot be greater than the number of hosts")
		}
		if flag&os.O_TRUNC == os.O_TRUNC {
			// remove existing file
			for fd, f := range fs.files {
				if f.name == name && f.closed {
					delete(fs.files, fd)
					break
				}
			}
		}
		hosts := make([]hostdb.HostPublicKey, 0, len(fs.hosts.sessions))
		for hostKey := range fs.hosts.sessions {
			hosts = append(hosts, hostKey)
		}
		m = renter.NewMetaFile(perm, 0, hosts, minShards)
	} else {
		var err error
		m, err = renter.ReadMetaFile(path)
		if err != nil {
			return nil, errors.Wrapf(err, "open %v", name)
		}
		// check whether we have a session for each of the file's hosts
		var missing []string
		for _, hostKey := range m.Hosts {
			if _, ok := fs.hosts.sessions[hostKey]; !ok {
				missing = append(missing, hostKey.ShortKey())
			}
		}
		if flag&rwmask == os.O_RDONLY {
			// only need m.MinShards hosts in order to read
			if have := len(m.Hosts) - len(missing); have < m.MinShards {
				return nil, errors.Errorf("insufficient contracts: need a contract from at least %v of these hosts: %v",
					m.MinShards-have, strings.Join(missing, " "))
			}
		} else {
			// need all hosts in order to write
			if len(missing) > 0 {
				return nil, errors.Errorf("insufficient contracts: need a contract from each of these hosts: %v",
					strings.Join(missing, " "))
			}
		}
	}
	of := &openMetaFile{
		name: name,
		m:    m,
	}
	if flag&os.O_APPEND == os.O_APPEND {
		of.offset = m.Filesize
	}
	fs.files[fs.curFD] = of
	fs.curFD++
	return &PseudoFile{
		name:  name,
		flags: flag,
		fd:    fs.curFD - 1,
		fs:    fs,
	}, nil
}

// Remove removes the named file or (empty) directory. It does NOT delete the
// file data on the host; use (PseudoFS).GC and (PseudoFile).Free for that.
func (fs *PseudoFS) Remove(name string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	// remove the file from fs.files if it is closed
	for fd, f := range fs.files {
		if f.name == name && f.closed {
			delete(fs.files, fd)
			break
		}
	}
	// delete the directory or metafile on disk
	path := fs.path(name)
	if !isDir(path) {
		path += metafileExt
	}
	return os.Remove(path)
}

// RemoveAll removes path and any children it contains. It removes everything it
// can but returns the first error it encounters. If the path does not exist,
// RemoveAll returns nil (no error).
func (fs *PseudoFS) RemoveAll(path string) error {
	// if the remove affects closed files in fs.files, delete them
	for fd, f := range fs.files {
		if strings.HasPrefix(f.name, path) && f.closed {
			delete(fs.files, fd)
		}
	}
	// delete the directories and metafiles on disk
	path = fs.path(path)
	if !isDir(path) {
		path += metafileExt
	}
	return os.RemoveAll(path)
}

// GC deletes unused data from the filesystem's host set. Any data not
// referenced by the files within the filesystem will be deleted. This has
// important implications for shared files: if you share a metafile and do not
// retain a local copy of it, then running GC will cause that file's data to be
// deleted, making it inaccessible.
//
// GC complements the (PseudoFile).Free method. Free cannot safely delete
// non-full sectors, because those sectors may be referenced by other files,
// e.g. when multiple files are packed into a single sector. GC is guaranteed to
// delete all unreferenced sectors, but is much slower than Free because it must
// examine the full filesystem. Free should be called frequently as a "first
// line of defense," while GC should be called infrequently to remove any
// sectors missed by Free.
func (fs *PseudoFS) GC() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Strategy: build a set of all sector roots stored on hosts. Iterate
	// through all files in the fs, deleting their sector roots from the set.
	// Any roots that remain in the set are unreferenced and may be deleted.

	// gather the sector roots from each host
	hostRoots := make(map[hostdb.HostPublicKey]map[crypto.Hash]struct{})
	for hostKey := range fs.hosts.sessions {
		err := func() error {
			h, err := fs.hosts.acquire(hostKey)
			if err != nil {
				return err
			}
			defer fs.hosts.release(hostKey)

			roots, err := h.SectorRoots(0, h.Revision().NumSectors())
			if err != nil {
				return err
			}
			rootMap := make(map[crypto.Hash]struct{}, len(roots))
			for _, r := range roots {
				rootMap[r] = struct{}{}
			}
			hostRoots[hostKey] = rootMap
			return nil
		}()
		if err != nil {
			return err
		}
	}

	// iterate through all files, deleting their sector roots from the set
	//
	// NOTE: we only iterate over the metafiles on disk, not the files
	// in-memory. We don't need to worry about the latter, because their sectors
	// have not been flushed to hosts yet.
	err := filepath.Walk(fs.root, func(path string, info os.FileInfo, _ error) error {
		if info.IsDir() || !strings.HasSuffix(path, ".usa") {
			return nil
		}
		m, err := renter.ReadMetaFile(path)
		if err != nil {
			// don't continue if a file couldn't be read; the user needs to be
			// confident that all files were checked
			return err
		}
		for i, hostKey := range m.Hosts {
			if roots, ok := hostRoots[hostKey]; ok {
				for _, ss := range m.Shards[i] {
					delete(roots, ss.MerkleRoot)
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// if there are no unreferenced sectors, we are done
	done := true
	for _, roots := range hostRoots {
		done = done && len(roots) == 0
	}
	if done {
		return nil
	}

	// delete the remaining sectors
	for hostKey, rootsMap := range hostRoots {
		err := func() error {
			h, err := fs.hosts.acquire(hostKey)
			if err != nil {
				return err
			}
			defer fs.hosts.release(hostKey)
			roots := make([]crypto.Hash, 0, len(rootsMap))
			for root := range rootsMap {
				roots = append(roots, root)
			}
			return h.DeleteSectors(roots)
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// Rename renames (moves) oldpath to newpath. If newpath already exists and is
// not a directory, Rename replaces it. OS-specific restrictions may apply when
// oldpath and newpath are in different directories.
func (fs *PseudoFS) Rename(oldname, newname string) error {
	// if there is an open file with oldname, we must sync its contents first
	fs.mu.Lock()
	for _, f := range fs.files {
		if f.name == oldname && len(f.pendingWrites) > 0 {
			if err := fs.flushSectors(); err != nil {
				return err
			}
			break
		}
	}
	fs.mu.Unlock()

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
	fs.mu.RLock()
	for _, f := range fs.files {
		if f.name == name {
			info := pseudoFileInfo{name: f.name, m: f.m.MetaIndex}
			info.m.Filesize = f.filesize()
			fs.mu.RUnlock()
			return info, nil
		}
	}
	fs.mu.RUnlock()

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

// Close closes the filesystem by flushing any uncommitted writes, closing any
// open files, and terminating all active host sessions.
func (fs *PseudoFS) Close() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if err := fs.flushSectors(); err != nil {
		return err
	}
	for fd, f := range fs.files {
		if err := fs.commitChanges(f); err != nil {
			return err
		}
		delete(fs.files, fd)
	}
	for fd, d := range fs.dirs {
		d.Close()
		delete(fs.dirs, fd)
	}
	return fs.hosts.Close()
}

// NewFileSystem returns a new pseudo-filesystem rooted at root, which must be a
// directory containing only metafiles and other directories.
func NewFileSystem(root string, hosts *HostSet) *PseudoFS {
	sectors := make(map[hostdb.HostPublicKey]*renter.SectorBuilder)
	for hostKey := range hosts.sessions {
		sectors[hostKey] = new(renter.SectorBuilder)
	}
	return &PseudoFS{
		root:           root,
		files:          make(map[int]*openMetaFile),
		dirs:           make(map[int]*os.File),
		hosts:          hosts,
		sectors:        sectors,
		lastCommitTime: time.Now(),
	}
}

// A PseudoFile presents a file-like interface for a metafile stored on Sia
// hosts.
type PseudoFile struct {
	name  string
	fd    int
	flags int
	fs    *PseudoFS
}

// ErrNotWriteable is returned for write operations on read-only files.
var ErrNotWriteable = errors.New("file is not writeable")

// ErrNotReadable is returned for read operations on write-only files.
var ErrNotReadable = errors.New("file is not readable")

// ErrAppendOnly is returned for seek operations on append-only files.
var ErrAppendOnly = errors.New("file is append-only")

// ErrDirectory is returned for operations that are not valid for directories.
var ErrDirectory = errors.New("file is a directory")

// ErrNotDirectory is returned for operations that are not valid for files.
var ErrNotDirectory = errors.New("file is not a directory")

const rwmask = os.O_RDONLY | os.O_WRONLY | os.O_RDWR

func (pf PseudoFile) writeable() bool {
	return pf.flags&rwmask == os.O_WRONLY || pf.flags&rwmask == os.O_RDWR
}
func (pf PseudoFile) readable() bool {
	return pf.flags&rwmask == os.O_RDONLY || pf.flags&rwmask == os.O_RDWR
}
func (pf PseudoFile) appendOnly() bool {
	return pf.flags&os.O_APPEND == os.O_APPEND
}

func (pf PseudoFile) lookupFD() (file *openMetaFile, dir *os.File) {
	file = pf.fs.files[pf.fd]
	if file != nil && file.closed {
		file = nil
	}
	return file, pf.fs.dirs[pf.fd]
}

// Close implements io.Closer.
func (pf PseudoFile) Close() error {
	pf.fs.mu.Lock()
	defer pf.fs.mu.Unlock()
	f, d := pf.lookupFD()
	if f == nil && d == nil {
		return ErrInvalidFileDescriptor
	} else if d != nil {
		delete(pf.fs.dirs, pf.fd)
		return d.Close()
	}
	// f is only truly deleted if it has no pending writes; otherwise, it sticks
	// around until the next flush
	if len(f.pendingWrites) == 0 {
		delete(pf.fs.files, pf.fd)
	}
	return nil
}

// Read implements io.Reader.
func (pf PseudoFile) Read(p []byte) (int, error) {
	if !pf.readable() {
		return 0, ErrNotReadable
	}
	// we need a write lock here because Read modifies the seek offset
	pf.fs.mu.Lock()
	defer pf.fs.mu.Unlock()
	f, d := pf.lookupFD()
	if f == nil && d == nil {
		return 0, ErrInvalidFileDescriptor
	} else if d != nil {
		return 0, ErrDirectory
	}
	return pf.fs.fileRead(f, p)
}

// Write implements io.Writer.
func (pf PseudoFile) Write(p []byte) (int, error) {
	if !pf.writeable() {
		return 0, ErrNotWriteable
	}
	pf.fs.mu.Lock()
	defer pf.fs.mu.Unlock()
	f, d := pf.lookupFD()
	if f == nil && d == nil {
		return 0, ErrInvalidFileDescriptor
	} else if d != nil {
		return 0, ErrDirectory
	}
	return pf.fs.fileWrite(f, p)
}

// ReadAt implements io.ReaderAt.
func (pf PseudoFile) ReadAt(p []byte, off int64) (int, error) {
	if !pf.readable() {
		return 0, ErrNotReadable
	}
	pf.fs.mu.RLock()
	defer pf.fs.mu.RUnlock()
	f, d := pf.lookupFD()
	if f == nil && d == nil {
		return 0, ErrInvalidFileDescriptor
	} else if d != nil {
		return 0, ErrDirectory
	}
	return pf.fs.fileReadAt(f, p, off)
}

// ReadAtP is a helper method that makes multiple concurrent ReadAt calls, with
// each call filling part of p. This may increase throughput depending on the
// file's redundancy. For example, if the file is stored at 2x redundancy, then
// in ideal circumstances, ReadAtP will be 2x faster than the equivalent ReadAt
// call.
//
// ReadAtP returns the first non-nil error returned by a ReadAt call. The
// contents of p are undefined if an error other than io.EOF is returned.
func (pf PseudoFile) ReadAtP(p []byte, off int64) (int, error) {
	if !pf.readable() {
		return 0, ErrNotReadable
	}
	pf.fs.mu.RLock()
	defer pf.fs.mu.RUnlock()
	f, d := pf.lookupFD()
	if f == nil && d == nil {
		return 0, ErrInvalidFileDescriptor
	} else if d != nil {
		return 0, ErrDirectory
	}

	splitSize := len(p) / (len(f.m.Hosts) / f.m.MinShards)
	if splitSize == 0 {
		return pf.fs.fileReadAt(f, p, off)
	}

	type readResult struct {
		n   int
		err error
	}
	resChan := make(chan readResult)
	var numResults int
	for buf := bytes.NewBuffer(p); buf.Len() > 0; {
		numResults++
		suboff := off + int64(len(p)-buf.Len())
		subp := buf.Next(splitSize)
		go func() {
			n, err := pf.fs.fileReadAt(f, subp, suboff)
			resChan <- readResult{n, err}
		}()
	}
	var n int
	var err error
	for i := 0; i < numResults; i++ {
		r := <-resChan
		n += r.n
		if r.err != nil && (err == nil || err == io.EOF) {
			err = r.err
		}
	}
	return n, err
}

// WriteAt implements io.WriterAt.
func (pf PseudoFile) WriteAt(p []byte, off int64) (int, error) {
	if !pf.writeable() {
		return 0, ErrNotWriteable
	}
	pf.fs.mu.Lock()
	defer pf.fs.mu.Unlock()
	f, d := pf.lookupFD()
	if f == nil && d == nil {
		return 0, ErrInvalidFileDescriptor
	} else if d != nil {
		return 0, ErrDirectory
	}
	if pf.appendOnly() && off != f.filesize() {
		return 0, ErrAppendOnly
	}
	return pf.fs.fileWriteAt(f, p, off)
}

// Seek implements io.Seeker.
func (pf PseudoFile) Seek(offset int64, whence int) (int64, error) {
	if pf.appendOnly() {
		return 0, ErrAppendOnly
	}
	pf.fs.mu.Lock()
	defer pf.fs.mu.Unlock()
	f, d := pf.lookupFD()
	if f == nil && d == nil {
		return 0, ErrInvalidFileDescriptor
	} else if d != nil {
		return 0, ErrDirectory
	}
	return pf.fs.fileSeek(f, offset, whence)
}

// Name returns the file's name, as passed to OpenFile.
func (pf PseudoFile) Name() string { return pf.name }

// Readdir reads the contents of the directory associated with pf and returns a
// slice of up to n FileInfo values, as would be returned by Lstat, in directory
// order. Subsequent calls on the same file will yield further FileInfos.
//
// If n > 0, Readdir returns at most n FileInfo structures. In this case, if
// Readdir returns an empty slice, it will return a non-nil error explaining
// why. At the end of a directory, the error is io.EOF.
//
// If n <= 0, Readdir returns all the FileInfo from the directory in a single
// slice. In this case, if Readdir succeeds (reads all the way to the end of the
// directory), it returns the slice and a nil error. If it encounters an error
// before the end of the directory, Readdir returns the FileInfo read until that
// point and a non-nil error.
func (pf PseudoFile) Readdir(n int) ([]os.FileInfo, error) {
	pf.fs.mu.RLock()
	defer pf.fs.mu.RUnlock()
	f, d := pf.lookupFD()
	if f == nil && d == nil {
		return nil, ErrInvalidFileDescriptor
	} else if d == nil {
		return nil, ErrNotDirectory
	}
	files, err := d.Readdir(n)
	for i := range files {
		if files[i].IsDir() {
			continue
		}
		index, err := renter.ReadMetaIndex(filepath.Join(d.Name(), files[i].Name()))
		if err != nil {
			return nil, err
		}
		files[i] = pseudoFileInfo{
			m:    index,
			name: strings.TrimSuffix(files[i].Name(), metafileExt),
		}
	}
outer:
	for _, f := range pf.fs.files {
		if filepath.Dir(filepath.Join(pf.fs.root, f.name)) == d.Name() {
			info := pseudoFileInfo{name: filepath.Base(f.name), m: f.m.MetaIndex}
			info.m.Filesize = f.filesize()
			for i := range files {
				if files[i].Name() == info.Name() {
					files[i] = info
					continue outer
				}
			}
			files = append(files, info)
		}
	}
	return files, err
}

// Readdirnames reads and returns a slice of names from the directory pf.
//
// If n > 0, Readdirnames returns at most n names. In this case, if Readdirnames
// returns an empty slice, it will return a non-nil error explaining why. At the
// end of a directory, the error is io.EOF.
//
// If n <= 0, Readdirnames returns all the names from the directory in a single
// slice. In this case, if Readdirnames succeeds (reads all the way to the end
// of the directory), it returns the slice and a nil error. If it encounters an
// error before the end of the directory, Readdirnames returns the names read
// until that point and a non-nil error.
func (pf PseudoFile) Readdirnames(n int) ([]string, error) {
	pf.fs.mu.RLock()
	defer pf.fs.mu.RUnlock()
	f, d := pf.lookupFD()
	if f == nil && d == nil {
		return nil, ErrInvalidFileDescriptor
	} else if d == nil {
		return nil, ErrNotDirectory
	}
	dirnames, err := d.Readdirnames(n)
	if err != nil {
		return nil, err
	}
	for _, f := range pf.fs.files {
		if filepath.Dir(filepath.Join(pf.fs.root, f.name)) == d.Name() {
			dirnames = append(dirnames, filepath.Base(f.name))
		}
	}
	return dirnames, nil
}

// Stat returns the FileInfo structure describing the file. If the file is a
// metafile, its renter.MetaIndex will be available via the Sys method.
func (pf PseudoFile) Stat() (os.FileInfo, error) {
	pf.fs.mu.RLock()
	defer pf.fs.mu.RUnlock()
	f, d := pf.lookupFD()
	if f == nil && d == nil {
		return nil, ErrInvalidFileDescriptor
	} else if d != nil {
		return d.Stat()
	}
	return pf.fs.fileStat(f)
}

// Sync commits the current contents of the file to stable storage. Any new data
// will be uploaded to hosts, and the metafile will be atomically updated to
// match the current state of the file. Calling Sync on one file may cause other
// files to be synced as well. Sync typically results in a full sector of data
// being uploaded to each host.
func (pf PseudoFile) Sync() error {
	if !pf.writeable() {
		return nil
	}
	pf.fs.mu.Lock()
	defer pf.fs.mu.Unlock()
	f, d := pf.lookupFD()
	if f == nil && d == nil {
		return ErrInvalidFileDescriptor
	} else if d != nil {
		return d.Sync()
	}
	return pf.fs.fileSync(f)
}

// Truncate changes the size of the file. It does not change the I/O offset. The
// new size must not exceed the current size.
func (pf PseudoFile) Truncate(size int64) error {
	if !pf.writeable() {
		return ErrNotWriteable
	}
	pf.fs.mu.Lock()
	defer pf.fs.mu.Unlock()
	f, d := pf.lookupFD()
	if f == nil && d == nil {
		return ErrInvalidFileDescriptor
	} else if d != nil {
		return ErrDirectory
	}
	return pf.fs.fileTruncate(f, size)
}

// Free truncates the file to 0 bytes and deletes file data from the
// filesystem's host set. Free only deletes sectors that it can prove are
// exclusively storing the file's data. If multiple files were packed into the
// same sector, Free will not delete that sector. Similarly, Free cannot safely
// delete "trailing" sectors at the end of a file. Use (PseudoFS).GC to delete
// such sectors after calling Remove on all the relevant files.
//
// Note that Free also discards any uncommitted Writes, so it may be necessary
// to call Sync prior to Free.
func (pf PseudoFile) Free() error {
	if !pf.writeable() {
		return ErrNotWriteable
	}
	pf.fs.mu.Lock()
	defer pf.fs.mu.Unlock()
	f, d := pf.lookupFD()
	if f == nil && d == nil {
		return ErrInvalidFileDescriptor
	} else if d != nil {
		return ErrDirectory
	}
	return pf.fs.fileFree(f)
}
