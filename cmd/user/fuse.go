package main

import (
	"io"
	"log"
	"os"
	"os/signal"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"
	"github.com/pkg/errors"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/renterutil"
)

func mount(contractDir, metaDir, mountDir string) error {
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
	nfs := pathfs.NewPathNodeFs(fileSystem(pfs), nil)
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
	return server.Unmount()
}

type fuseFS struct {
	pathfs.FileSystem
	pfs *renterutil.PseudoFS
}

// GetAttr implements the GetAttr method of pathfs.FileSystem.
func (fs *fuseFS) GetAttr(name string, _ *fuse.Context) (*fuse.Attr, fuse.Status) {
	stat, err := fs.pfs.Stat(name)
	if err != nil {
		return nil, fuse.ENOENT
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

// OpenDir implements the OpenDir method of pathfs.FileSystem.
func (fs *fuseFS) OpenDir(name string, context *fuse.Context) ([]fuse.DirEntry, fuse.Status) {
	dir, err := fs.pfs.Open(name)
	if err != nil {
		return nil, fuse.ENOENT
	}
	defer dir.Close()
	files, err := dir.Readdir(-1)
	if err != nil {
		return nil, fuse.ENOENT
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

// Open implements the Open method of pathfs.FileSystem.
func (fs *fuseFS) Open(name string, flags uint32, context *fuse.Context) (file nodefs.File, code fuse.Status) {
	if flags&fuse.O_ANYWRITE != 0 {
		return nil, fuse.EPERM
	}

	pf, err := fs.pfs.Open(name)
	if err != nil {
		return nil, fuse.ENOENT
	}
	return &metaFSFile{
		File: nodefs.NewDefaultFile(),
		pf:   pf,
	}, fuse.OK
}

func fileSystem(pfs *renterutil.PseudoFS) *fuseFS {
	return &fuseFS{
		FileSystem: pathfs.NewDefaultFileSystem(),
		pfs:        pfs,
	}
}

type metaFSFile struct {
	nodefs.File
	pf *renterutil.PseudoFile
}

func (f *metaFSFile) Read(p []byte, off int64) (fuse.ReadResult, fuse.Status) {
	if _, err := f.pf.Seek(off, io.SeekStart); err != nil {
		return nil, fuse.ENOENT
	}
	n, err := f.pf.Read(p)
	if err != nil && err != io.EOF {
		return nil, fuse.ENOENT
	}
	return fuse.ReadResultData(p[:n]), fuse.OK
}
