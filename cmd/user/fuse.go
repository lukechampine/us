package main

import (
	"bufio"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"
	"github.com/pkg/errors"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/renterutil"
)

func mount(contractDir, metaDir, mountDir string, minShards int) error {
	contracts, err := renter.LoadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer contracts.Close()

	c := makeLimitedClient()
	currentHeight, err := c.ChainHeight()
	if err != nil {
		return err
	}
	pfs := renterutil.NewFileSystem(metaDir, contracts, c, currentHeight)
	nfs := pathfs.NewPathNodeFs(fileSystem(pfs, minShards), nil)
	server, _, err := nodefs.MountRoot(mountDir, nfs.Root(), nil)
	if err != nil {
		return errors.Wrap(err, "could not mount")
	}
	log.Println("Mounted!")
	go server.Serve()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	<-sigChan
	log.Println("Unmounting...")
	if err := pfs.Close(); err != nil {
		log.Println("Error during close:", err)
	}
	return server.Unmount()
}

func errToStatus(op, name string, err error) fuse.Status {
	if err == nil {
		return fuse.OK
	} else if os.IsNotExist(errors.Cause(err)) {
		return fuse.ENOENT
	}
	log.Printf("%v %v: %v", op, name, err)
	return fuse.EIO
}

type fuseFS struct {
	pathfs.FileSystem
	pfs       *renterutil.PseudoFS
	minShards int
}

// GetAttr implements pathfs.FileSystem.
func (fs *fuseFS) GetAttr(name string, _ *fuse.Context) (*fuse.Attr, fuse.Status) {
	stat, err := fs.pfs.Stat(name)
	if err != nil {
		return nil, errToStatus("GetAttr", name, err)
	}
	var mode uint32
	if stat.IsDir() {
		mode = fuse.S_IFDIR
	} else {
		mode = fuse.S_IFREG
	}
	return &fuse.Attr{
		Size:  uint64(stat.Size()),
		Mode:  mode | uint32(stat.Mode()),
		Mtime: uint64(stat.ModTime().Unix()),
	}, fuse.OK
}

// OpenDir implements pathfs.FileSystem.
func (fs *fuseFS) OpenDir(name string, _ *fuse.Context) ([]fuse.DirEntry, fuse.Status) {
	dir, err := fs.pfs.Open(name)
	if err != nil {
		return nil, errToStatus("OpenDir", name, err)
	}
	defer dir.Close()
	files, err := dir.Readdir(-1)
	if err != nil {
		return nil, errToStatus("OpenDir", name, err)
	}
	entries := make([]fuse.DirEntry, len(files))
	for i, f := range files {
		name := f.Name()
		mode := uint32(f.Mode())
		if f.IsDir() {
			mode |= fuse.S_IFDIR
		} else {
			mode |= fuse.S_IFREG
		}
		entries[i] = fuse.DirEntry{
			Name: name,
			Mode: mode,
		}
	}
	return entries, fuse.OK
}

// Open implements pathfs.FileSystem.
func (fs *fuseFS) Open(name string, flags uint32, _ *fuse.Context) (file nodefs.File, code fuse.Status) {
	flags &= fuse.O_ANYWRITE | uint32(os.O_APPEND)
	pf, err := fs.pfs.OpenFile(name, int(flags), 0, fs.minShards)
	if err != nil {
		return nil, errToStatus("Open", name, err)
	}
	return &metaFSFile{
		File: nodefs.NewDefaultFile(),
		pf:   pf,
	}, fuse.OK
}

// Create implements pathfs.FileSystem.
func (fs *fuseFS) Create(name string, flags uint32, mode uint32, _ *fuse.Context) (file nodefs.File, code fuse.Status) {
	pf, err := fs.pfs.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.FileMode(mode), fs.minShards)
	if err != nil {
		return nil, errToStatus("Create", name, err)
	}
	return &metaFSFile{
		File: nodefs.NewDefaultFile(),
		pf:   pf,
	}, fuse.OK
}

// Unlink implements pathfs.FileSystem.
func (fs *fuseFS) Unlink(name string, _ *fuse.Context) (code fuse.Status) {
	if err := fs.pfs.Remove(name); err != nil {
		return errToStatus("Unlink", name, err)
	}
	return fuse.OK
}

// Rename implements pathfs.FileSystem.
func (fs *fuseFS) Rename(oldName string, newName string, context *fuse.Context) (code fuse.Status) {
	if err := fs.pfs.Rename(oldName, newName); err != nil {
		return errToStatus("Rename", oldName, err)
	}
	return fuse.OK
}

// Mkdir implements pathfs.FileSystem.
func (fs *fuseFS) Mkdir(name string, mode uint32, context *fuse.Context) (code fuse.Status) {
	if err := fs.pfs.MkdirAll(name, os.FileMode(mode)); err != nil {
		return errToStatus("Mkdir", name, err)
	}
	return fuse.OK
}

// Rmdir implements pathfs.FileSystem.
func (fs *fuseFS) Rmdir(name string, _ *fuse.Context) (code fuse.Status) {
	if err := fs.pfs.RemoveAll(name); err != nil {
		return errToStatus("Rmdir", name, err)
	}
	return fuse.OK
}

// Chmod implements pathfs.FileSystem.
func (fs *fuseFS) Chmod(name string, mode uint32, context *fuse.Context) (code fuse.Status) {
	if err := fs.pfs.Chmod(name, os.FileMode(mode)); err != nil {
		return errToStatus("Chmod", name, err)
	}
	return fuse.OK
}

func fileSystem(pfs *renterutil.PseudoFS, minShards int) *fuseFS {
	return &fuseFS{
		FileSystem: pathfs.NewDefaultFileSystem(),
		pfs:        pfs,
		minShards:  minShards,
	}
}

type metaFSFile struct {
	nodefs.File
	pf *renterutil.PseudoFile

	mu      sync.Mutex
	br      *bufio.Reader
	lastOff int64
}

func (f *metaFSFile) Read(p []byte, off int64) (fuse.ReadResult, fuse.Status) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.br == nil || off != f.lastOff {
		stat, _ := f.pf.Stat()
		sr := io.NewSectionReader(f.pf, off, stat.Size()-off)
		if f.br == nil {
			f.br = bufio.NewReaderSize(sr, 1<<20) // 1 MB
		} else {
			f.br.Reset(sr)
		}
	}
	n, err := f.br.Read(p)
	if err != nil && err != io.EOF {
		return nil, errToStatus("Read", f.pf.Name(), err)
	}
	f.lastOff = off + int64(n)
	return fuse.ReadResultData(p[:n]), fuse.OK
}

func (f *metaFSFile) Write(p []byte, off int64) (written uint32, code fuse.Status) {
	n, err := f.pf.WriteAt(p, off)
	if err != nil {
		return 0, errToStatus("Write", f.pf.Name(), err)
	}
	return uint32(n), fuse.OK
}

func (f *metaFSFile) Truncate(size uint64) fuse.Status {
	if err := f.pf.Truncate(int64(size)); err != nil {
		return errToStatus("Truncate", f.pf.Name(), err)
	}
	return fuse.OK
}

func (f *metaFSFile) Flush() fuse.Status {
	return fuse.OK
}

func (f *metaFSFile) Release() {
	if err := f.pf.Close(); err != nil {
		_ = errToStatus("Release", f.pf.Name(), err)
	}
}

func (f *metaFSFile) Fsync(flags int) fuse.Status {
	if err := f.pf.Sync(); err != nil {
		return errToStatus("Fsync", f.pf.Name(), err)
	}
	return fuse.OK
}
