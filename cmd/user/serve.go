package main

import (
	"bufio"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"lukechampine.com/us/renter/renterutil"

	"github.com/pkg/errors"
	"lukechampine.com/us/renter"
)

func serve(contractDir, metaDir, addr string) error {
	contracts, err := renter.LoadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer contracts.Close()

	c := makeLimitedClient()
	downloaders, err := renterutil.NewDownloaderSet(contracts, c)
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
		downloaders.Close()
	}()
	log.Printf("Listening on %v...", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// metaInfo implements the os.FileInfo for a metafile.
type metaInfo struct {
	m    renter.MetaIndex
	name string
}

func (i metaInfo) Name() string       { return i.name }
func (i metaInfo) Size() int64        { return i.m.Filesize }
func (i metaInfo) Mode() os.FileMode  { return i.m.Mode }
func (i metaInfo) ModTime() time.Time { return i.m.ModTime }
func (i metaInfo) IsDir() bool        { return false }
func (i metaInfo) Sys() interface{}   { return nil }

// metaDir implements http.File for a directory of metafiles.
type metaDir struct {
	*os.File
	dir string
}

func (d metaDir) Readdir(n int) ([]os.FileInfo, error) {
	files, err := d.File.Readdir(n)
	for i := range files {
		if files[i].IsDir() {
			continue
		}
		index, err := renter.ReadMetaIndex(filepath.Join(d.dir, files[i].Name()))
		if err != nil {
			return nil, err
		}
		files[i] = metaInfo{
			m:    index,
			name: strings.TrimSuffix(files[i].Name(), metafileExt),
		}
	}
	return files, err
}

// A httpFile implements the http.File interface by downloading data from
// Sia hosts.
type httpFile struct {
	metaInfo
	*renterutil.PseudoFile
	br *bufio.Reader
}

func (f *httpFile) Read(p []byte) (int, error)         { return f.br.Read(p) }
func (f *httpFile) Close() error                       { return nil }
func (f *httpFile) Readdir(int) ([]os.FileInfo, error) { return nil, nil }
func (f *httpFile) Stat() (os.FileInfo, error)         { return f.metaInfo, nil }

// HTTPFile returns an http.File for the specified metafile.
func HTTPFile(name string, downloaders *renterutil.DownloaderSet) (http.File, error) {
	m, err := renter.OpenMetaFile(name)
	if err != nil {
		return nil, err
	}
	defer m.Close()
	pf, err := renterutil.NewPseudoFile(m, downloaders)
	if err != nil {
		return nil, err
	}
	return &httpFile{
		metaInfo: metaInfo{
			m:    m.MetaIndex,
			name: strings.TrimSuffix(name, metafileExt),
		},
		PseudoFile: pf,
		br:         bufio.NewReaderSize(pf, 1<<20), // 1 MiB
	}, nil
}

type httpFS struct {
	root        string
	downloaders *renterutil.DownloaderSet
}

func (fs *httpFS) tryOpen(name string) (http.File, error) {
	name = filepath.Join(fs.root, name)
	if stat, err := os.Stat(name); err != nil {
		return nil, errors.Wrap(err, "could not stat file")
	} else if stat.IsDir() {
		d, err := os.Open(name)
		return metaDir{d, name}, err
	}
	return HTTPFile(name, fs.downloaders)
}

func (fs *httpFS) Open(name string) (http.File, error) {
	// name is probably a metafile, so first try to append with .usa appended.
	// If that file doesn't exist, fall back to the unmodified name.
	if f, err := fs.tryOpen(name + metafileExt); !os.IsNotExist(errors.Cause(err)) {
		return f, err
	}
	return fs.tryOpen(name)
}

// httpDir returns an object that implements http.FileSystem for the given
// metafile root directory.
func httpDir(root string, downloaders *renterutil.DownloaderSet) http.FileSystem {
	return &httpFS{
		root:        root,
		downloaders: downloaders,
	}
}
