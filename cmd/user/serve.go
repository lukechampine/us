package main

import (
	"bufio"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/pkg/errors"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/renterutil"
)

func serve(contractDir, metaDir, addr string) error {
	contracts, err := renter.LoadContracts(contractDir)
	if err != nil {
		return errors.Wrap(err, "could not load contracts")
	}
	defer contracts.Close()

	c := makeLimitedClient()
	currentHeight, err := c.ChainHeight()
	if err != nil {
		return errors.Wrap(err, "could not determine current height")
	}
	pfs := renterutil.NewFileSystem(metaDir, contracts, c, currentHeight)
	srv := &http.Server{
		Addr:    addr,
		Handler: http.FileServer(&httpFS{pfs}),
	}
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt)
		<-sigChan
		log.Println("Stopping server...")
		srv.Close()
		pfs.Close()
	}()
	log.Printf("Listening on %v...", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// A bufferedFile wraps a renterutil.PseudoFile in a bufio.Reader for better
// performance.
type bufferedFile struct {
	*renterutil.PseudoFile
	br *bufio.Reader
}

func (f *bufferedFile) Read(p []byte) (int, error) {
	if f.br == nil {
		f.br = bufio.NewReaderSize(f.PseudoFile, 1<<20) // 1 MiB
	}
	return f.br.Read(p)
}

func (f *bufferedFile) Seek(offset int64, whence int) (int64, error) {
	f.br = nil // have to throw away buffer after each seek
	return f.PseudoFile.Seek(offset, whence)
}

type httpFS struct {
	pfs *renterutil.PseudoFS
}

func (hfs *httpFS) Open(name string) (http.File, error) {
	pf, err := hfs.pfs.Open(name)
	if err != nil {
		return nil, err
	}
	return &bufferedFile{
		PseudoFile: pf,
	}, nil
}
