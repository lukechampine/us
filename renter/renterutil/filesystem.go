package renterutil

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/types"
	"gitlab.com/NebulousLabs/fastrand"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter"
)

var errInvalidFileDescriptor = errors.New("invalid file descriptor")

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
	root           string
	curFD          int
	files          map[int]*openMetaFile
	dirs           map[int]*os.File
	hosts          *HostSet
	sectors        map[hostdb.HostPublicKey]*renter.SectorBuilder
	lastCommitTime time.Time
	mu             sync.Mutex
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
	// TODO: make this much more robust
	for fd, of := range fs.files {
		if of.name == name {
			of.closed = false
			if flag&os.O_APPEND != 0 {
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
	var index renter.MetaIndex
	var shards [][]renter.SectorSlice
	if flag == os.O_CREATE|os.O_TRUNC|os.O_RDWR {
		index = renter.MetaIndex{
			Version:   renter.MetaFileVersion,
			Mode:      perm,
			MinShards: minShards,
			ModTime:   time.Now(),
		}
		fastrand.Read(index.MasterKey[:])
		for hostKey := range fs.hosts.sessions {
			index.Hosts = append(index.Hosts, hostKey)
		}
		shards = make([][]renter.SectorSlice, len(index.Hosts))
	} else if flag == os.O_WRONLY|os.O_APPEND {
		var err error
		index, shards, err = renter.ReadMetaFileContents(path)
		if err != nil {
			return nil, errors.Wrapf(err, "open %v", name)
		}
		fs.files[fs.curFD] = &openMetaFile{
			name:   name,
			m:      index,
			shards: shards,
			offset: index.Filesize,
		}
		fs.curFD++
		return &PseudoFile{
			name:  name,
			flags: flag,
			fd:    fs.curFD - 1,
			fs:    fs,
		}, nil

	} else if flag == os.O_RDONLY {
		var err error
		index, shards, err = renter.ReadMetaFileContents(path)
		if err != nil {
			return nil, errors.Wrapf(err, "open %v", name)
		}
	} else {
		return nil, errors.New("unsupported flag combination")
	}

	fs.files[fs.curFD] = &openMetaFile{
		name:   name,
		m:      index,
		shards: shards,
	}
	fs.curFD++
	return &PseudoFile{
		name:  name,
		flags: flag,
		fd:    fs.curFD - 1,
		fs:    fs,
	}, nil
}

// Remove removes the named file or (empty) directory.
func (fs *PseudoFS) Remove(name string) error {
	// TODO: delete remote sectors?
	// TODO: how does this interact with open files?
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
	fs.mu.Lock()
	for _, f := range fs.files {
		if f.name == name {
			info := pseudoFileInfo{name: f.name, m: f.m}
			info.m.Filesize = f.filesize()
			fs.mu.Unlock()
			return info, nil
		}
	}
	fs.mu.Unlock()

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
func NewFileSystem(root string, contracts renter.ContractSet, hkr renter.HostKeyResolver, currentHeight types.BlockHeight) *PseudoFS {
	sectors := make(map[hostdb.HostPublicKey]*renter.SectorBuilder)
	for hostKey := range contracts {
		sectors[hostKey] = new(renter.SectorBuilder)
	}
	return &PseudoFS{
		root:           root,
		files:          make(map[int]*openMetaFile),
		dirs:           make(map[int]*os.File),
		hosts:          NewHostSet(contracts, hkr, currentHeight),
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
		return errInvalidFileDescriptor
	} else if d != nil {
		delete(pf.fs.dirs, pf.fd)
		return d.Close()
	}
	f.closed = true
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
	pf.fs.mu.Lock()
	defer pf.fs.mu.Unlock()
	f, d := pf.lookupFD()
	if f == nil && d == nil {
		return 0, errInvalidFileDescriptor
	} else if d != nil {
		return d.Read(p)
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
		return 0, errInvalidFileDescriptor
	} else if d != nil {
		return d.Write(p)
	}
	return pf.fs.fileWrite(f, p)
}

// ReadAt implements io.ReaderAt.
func (pf PseudoFile) ReadAt(p []byte, off int64) (int, error) {
	if !pf.readable() {
		return 0, ErrNotReadable
	}
	pf.fs.mu.Lock()
	defer pf.fs.mu.Unlock()
	f, d := pf.lookupFD()
	if f == nil && d == nil {
		return 0, errInvalidFileDescriptor
	} else if d != nil {
		return d.ReadAt(p, off)
	}
	return pf.fs.fileReadAt(f, p, off)
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
		return 0, errInvalidFileDescriptor
	} else if d != nil {
		return d.WriteAt(p, off)
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
		return 0, errInvalidFileDescriptor
	} else if d != nil {
		return d.Seek(offset, whence)
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
	pf.fs.mu.Lock()
	defer pf.fs.mu.Unlock()
	f, d := pf.lookupFD()
	if f == nil && d == nil {
		return nil, errInvalidFileDescriptor
	} else if d == nil {
		return nil, errors.New("not a directory")
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
	for _, f := range pf.fs.files {
		if filepath.Dir(filepath.Join(pf.fs.root, f.name)) == d.Name() {
			info := pseudoFileInfo{name: filepath.Base(f.name), m: f.m}
			info.m.Filesize = f.filesize()
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
	pf.fs.mu.Lock()
	defer pf.fs.mu.Unlock()
	f, d := pf.lookupFD()
	if f == nil && d == nil {
		return nil, errInvalidFileDescriptor
	} else if d == nil {
		return nil, errors.New("not a directory")
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
	pf.fs.mu.Lock()
	defer pf.fs.mu.Unlock()
	f, d := pf.lookupFD()
	if f == nil && d == nil {
		return nil, errInvalidFileDescriptor
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
		return errInvalidFileDescriptor
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
		return errInvalidFileDescriptor
	} else if d != nil {
		return d.Truncate(size)
	}
	return pf.fs.fileTruncate(f, size)
}
