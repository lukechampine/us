package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/terminal"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/renterutil"
	"lukechampine.com/us/renterhost"
)

type trackWriter struct {
	w                io.Writer
	name             string
	off, xfer, total int64
	start            time.Time
	sigChan          <-chan os.Signal
}

func (tw *trackWriter) Write(p []byte) (int, error) {
	// check for cancellation
	select {
	case <-tw.sigChan:
		return 0, context.Canceled
	default:
	}
	n, err := tw.w.Write(p)
	tw.xfer += int64(n)
	printSimpleProgress(tw.name, tw.off, tw.xfer, tw.total, time.Since(tw.start))
	return n, err
}

func trackDownload(f *os.File, pf *renterutil.PseudoFile, off int64) error {
	stat, err := pf.Stat()
	if err != nil {
		return err
	}
	if off == stat.Size() {
		printAlreadyFinished(f.Name(), off)
		fmt.Println()
		return nil
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGPIPE)
	tw := &trackWriter{
		w:       f,
		name:    f.Name(),
		off:     off,
		total:   stat.Size(),
		start:   time.Now(),
		sigChan: sigChan,
	}
	index := stat.Sys().(renter.MetaIndex)
	buf := make([]byte, renterhost.SectorSize*index.MinShards)
	_, err = io.CopyBuffer(tw, pf, buf)
	if err == context.Canceled {
		err = nil
	}
	fmt.Println()
	return err
}

func trackUpload(pf *renterutil.PseudoFile, f *os.File) error {
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	pstat, err := pf.Stat()
	if err != nil {
		return err
	}
	if pstat.Size() == stat.Size() {
		printAlreadyFinished(f.Name(), pstat.Size())
		fmt.Println()
		return nil
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGPIPE)
	tw := &trackWriter{
		w:       pf,
		name:    f.Name(),
		off:     pstat.Size(),
		total:   stat.Size(),
		start:   time.Now(),
		sigChan: sigChan,
	}
	index := pstat.Sys().(renter.MetaIndex)
	buf := make([]byte, renterhost.SectorSize*index.MinShards)
	_, err = io.CopyBuffer(tw, f, buf)
	if err == context.Canceled {
		err = nil
	}
	fmt.Println()
	return err
}

func trackMigrateFile(filename string, op *renterutil.Operation) error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGPIPE)

	migrateStart := time.Now()
	for {
		select {
		case u, ok := <-op.Updates():
			if !ok {
				fmt.Println()
				return op.Err()
			}
			switch u := u.(type) {
			case renterutil.TransferProgressUpdate:
				printOperationProgress(filename, u, time.Since(migrateStart))
			}
		case <-sigChan:
			fmt.Println("\rStopping...")
			op.Cancel()
			for range op.Updates() {
			}
			return nil
		}
	}
}

func trackMigrateDir(op *renterutil.Operation) error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGPIPE)

	var filename string
	var migrateStart time.Time
	for {
		select {
		case u, ok := <-op.Updates():
			if !ok {
				return op.Err()
			}
			switch u := u.(type) {
			case renterutil.DirQueueUpdate:
				if filename != "" {
					fmt.Println()
				}
				filename = u.Filename
				migrateStart = time.Now()
				p := renterutil.TransferProgressUpdate{
					Total:       u.Filesize,
					Transferred: 0,
				}
				printOperationProgress(filename, p, time.Since(migrateStart))
			case renterutil.TransferProgressUpdate:
				printOperationProgress(filename, u, time.Since(migrateStart))
			case renterutil.DirSkipUpdate:
				fmt.Printf("Skip %v: %v\n", u.Filename, u.Err)
				filename = ""
			}
		case <-sigChan:
			fmt.Println("\nStopping...")
			op.Cancel()
			for range op.Updates() {
			}
			if op.Err() != renterutil.ErrCanceled {
				return op.Err()
			}
			return nil
		}
	}
}

// progress bar helpers

func formatFilename(name string, maxLen int) string {
	//name = filepath.Base(name)
	if len(name) > maxLen {
		name = name[:maxLen]
	}
	return name
}

func getWidth() int {
	termWidth, _, err := terminal.GetSize(0)
	if err != nil {
		return 80 // sane default
	}
	return termWidth
}

func makeBuf(width int) []rune {
	buf := make([]rune, width)
	for i := range buf {
		buf[i] = ' '
	}
	return buf
}

func printSimpleProgress(filename string, start, xfer, total int64, elapsed time.Duration) {
	termWidth := getWidth()
	bytesPerSec := int64(float64(xfer) / elapsed.Seconds())
	pct := (100 * (start + xfer)) / total
	metrics := fmt.Sprintf("%4v%%   %8s  %9s/s    ", pct, filesizeUnits(total), filesizeUnits(bytesPerSec))
	name := formatFilename(filename, termWidth-len(metrics)-4)
	buf := makeBuf(termWidth)
	copy(buf, []rune(name))
	copy(buf[len(buf)-len(metrics):], []rune(metrics))
	fmt.Printf("\r%s", string(buf))
}

func printAlreadyFinished(filename string, total int64) {
	termWidth := getWidth()
	metrics := fmt.Sprintf("%4v%%   %8s  %9s/s    ", 100.0, filesizeUnits(total), "--- B")
	name := formatFilename(filename, termWidth-len(metrics)-4)
	buf := makeBuf(termWidth)
	copy(buf, []rune(name))
	copy(buf[len(buf)-len(metrics):], []rune(metrics))
	fmt.Printf("\r%s", string(buf))
}

func printOperationProgress(filename string, u renterutil.TransferProgressUpdate, elapsed time.Duration) {
	printSimpleProgress(filename, u.Start, u.Transferred, u.Total, elapsed)
}
