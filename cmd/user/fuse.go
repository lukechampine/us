package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"lukechampine.com/us/renter"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"
)

func mount(contractDir, metaDir, mountDir string) error {
	contracts, err := renter.LoadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer contracts.Close()

	c := makeLimitedClient()
	downloaders, err := newDownloaderSet(contracts, c)
	if err != nil {
		return errors.Wrap(err, "could not connect to hosts")
	}
	nfs := pathfs.NewPathNodeFs(fileSystem(metaDir, downloaders), nil)
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

// PseudoFS implements a FUSE filesystem by downloading data from Sia hosts.
type PseudoFS struct {
	pathfs.FileSystem

	root        string
	downloaders *downloaderSet
}

// GetAttr implements the GetAttr method of pathfs.FileSystem.
func (fs *PseudoFS) GetAttr(name string, _ *fuse.Context) (*fuse.Attr, fuse.Status) {
	path := filepath.Join(fs.root, name)
	if stat, err := os.Stat(path); err == nil && stat.IsDir() {
		return &fuse.Attr{
			Mode: fuse.S_IFDIR | 0755,
		}, fuse.OK
	} else if os.IsNotExist(err) {
		path += metafileExt
	}
	index, err := renter.ReadMetaIndex(path)
	if err != nil {
		return nil, fuse.ENOENT
	}
	return &fuse.Attr{
		Size:  uint64(index.Filesize),
		Mode:  fuse.S_IFREG | uint32(index.Mode),
		Mtime: uint64(index.ModTime.Unix()),
	}, fuse.OK
}

// OpenDir implements the OpenDir method of pathfs.FileSystem.
func (fs *PseudoFS) OpenDir(name string, context *fuse.Context) ([]fuse.DirEntry, fuse.Status) {
	path := filepath.Join(fs.root, name)
	dir, err := os.Open(path)
	if err != nil {
		return nil, fuse.ENOENT
	}
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
			name = strings.TrimSuffix(name, metafileExt)
		}
		entries[i] = fuse.DirEntry{
			Name: name,
			Mode: mode,
		}
	}
	return entries, fuse.OK
}

// Open implements the Open method of pathfs.FileSystem.
func (fs *PseudoFS) Open(name string, flags uint32, context *fuse.Context) (file nodefs.File, code fuse.Status) {
	if flags&fuse.O_ANYWRITE != 0 {
		return nil, fuse.EPERM
	}

	path := filepath.Join(fs.root, name) + metafileExt
	hf, err := HTTPFile(path, fs.downloaders)
	if err != nil {
		return nil, fuse.ENOENT
	}

	return &metaFSFile{
		File: nodefs.NewDefaultFile(),
		hf:   hf,
	}, fuse.OK
}

// fileSystem returns a PseudoFS rooted at the specified root.
func fileSystem(root string, downloaders *downloaderSet) *PseudoFS {
	return &PseudoFS{
		FileSystem:  pathfs.NewDefaultFileSystem(),
		root:        root,
		downloaders: downloaders,
	}
}

type metaFSFile struct {
	nodefs.File
	hf http.File
}

func (f *metaFSFile) Read(p []byte, off int64) (fuse.ReadResult, fuse.Status) {
	if _, err := f.hf.Seek(off, io.SeekStart); err != nil {
		return nil, fuse.ENOENT
	}
	n, err := f.hf.Read(p)
	if err != nil && err != io.EOF {
		return nil, fuse.ENOENT
	}
	return fuse.ReadResultData(p[:n]), fuse.OK
}
