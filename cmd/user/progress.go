package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/lukechampine/us/renter/renterutil"
	"golang.org/x/crypto/ssh/terminal"
)

func trackUpload(filename string, op *renterutil.Operation) error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	var uploadStart time.Time
	for {
		select {
		case u, ok := <-op.Updates():
			if !ok {
				fmt.Println()
				return op.Err()
			}
			switch u := u.(type) {
			case renterutil.TransferProgressUpdate:
				if uploadStart.IsZero() {
					uploadStart = time.Now()
				}
				printSimpleProgress(filename, u, time.Since(uploadStart))
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

func trackDownload(filename string, op *renterutil.Operation) error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	var downloadStart time.Time
	for {
		select {
		case u, ok := <-op.Updates():
			if !ok {
				fmt.Println()
				return op.Err()
			}
			switch u := u.(type) {
			case renterutil.TransferProgressUpdate:
				if downloadStart.IsZero() {
					downloadStart = time.Now()
				}
				printSimpleProgress(filename, u, time.Since(downloadStart))
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

func trackDownloadStream(op *renterutil.Operation) error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	for {
		select {
		case _, ok := <-op.Updates():
			if !ok {
				return op.Err()
			}
		case <-sigChan:
			op.Cancel()
			for range op.Updates() {
			}
			return nil
		}
	}
}

func trackDownloadDir(op *renterutil.Operation) error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	var filename string
	var downloadStart time.Time
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
				downloadStart = time.Now()
				p := renterutil.TransferProgressUpdate{
					Total:       u.Filesize,
					Transferred: 0,
				}
				printSimpleProgress(filename, p, time.Since(downloadStart))
			case renterutil.TransferProgressUpdate:
				printSimpleProgress(filename, u, time.Since(downloadStart))
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

func trackUploadDir(op *renterutil.Operation) error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	var queue []renterutil.DirQueueUpdate
	var uploadStart time.Time
	var newQueue bool
	for {
		select {
		case u, ok := <-op.Updates():
			if !ok {
				// TODO: don't print 100% if there was an error
				printUploadDirFinished(queue, uploadStart)
				return op.Err()
			}
			switch u := u.(type) {
			case renterutil.DirQueueUpdate:
				// don't add duplicate elements to the queue
				if len(queue) > 0 && u == queue[len(queue)-1] {
					continue
				}
				if newQueue {
					printUploadDirFinished(queue, uploadStart)
					queue = queue[:0]
					newQueue = false
				}
				queue = append(queue, u)
				uploadStart = time.Now()
			case renterutil.TransferProgressUpdate:
				newQueue = true
				printUploadDirProgress(queue, u, uploadStart)
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

func trackMigrateFile(filename string, op *renterutil.Operation) error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

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
				printSimpleProgress(filename, u, time.Since(migrateStart))
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
	signal.Notify(sigChan, os.Interrupt)

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
				printSimpleProgress(filename, p, time.Since(migrateStart))
			case renterutil.TransferProgressUpdate:
				printSimpleProgress(filename, u, time.Since(migrateStart))
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

func printSimpleProgress(filename string, u renterutil.TransferProgressUpdate, elapsed time.Duration) {
	termWidth := getWidth()
	bytesPerSec := int64(float64(u.Transferred) / elapsed.Seconds())
	pct := (100 * (u.Start + u.Transferred)) / u.Total
	metrics := fmt.Sprintf("%4v%%   %8s  %9s/s    ", pct, filesizeUnits(u.Total), filesizeUnits(bytesPerSec))
	name := formatFilename(filename, termWidth-len(metrics)-4)
	buf := makeBuf(termWidth)
	copy(buf, []rune(name))
	copy(buf[len(buf)-len(metrics):], []rune(metrics))
	fmt.Printf("\r%s", string(buf))
}

func printUploadDirProgress(queue []renterutil.DirQueueUpdate, u renterutil.TransferProgressUpdate, start time.Time) {
	termWidth := getWidth()
	elapsed := time.Since(start)
	bytesPerSec := int64(float64(u.Transferred) / elapsed.Seconds())
	pct := (100 * (u.Start + u.Transferred)) / u.Total
	metrics := fmt.Sprintf("%4v%%   %8s  %9s/s    ", pct, filesizeUnits(u.Total), filesizeUnits(bytesPerSec))
	var name string
	if len(queue) == 1 {
		name = formatFilename(queue[0].Filename, termWidth-len(metrics)-4)
	} else {
		more := fmt.Sprintf("(+%d more)", len(queue)-1)
		maxLen := termWidth - len(metrics) - len(more) - 4
		name = fmt.Sprintf("%s %s", formatFilename(queue[0].Filename, maxLen), more)
	}

	buf := makeBuf(termWidth)
	copy(buf, []rune(name))
	copy(buf[len(buf)-len(metrics):], []rune(metrics))
	fmt.Printf("\r%s", string(buf))
}

func printUploadDirFinished(queue []renterutil.DirQueueUpdate, start time.Time) {
	if len(queue) == 0 {
		return
	}
	termWidth := getWidth()
	elapsed := time.Since(start)
	var totalSize int64
	for _, f := range queue {
		totalSize += f.Filesize
	}
	bytesPerSec := int64(float64(totalSize) / elapsed.Seconds())
	fmt.Printf("\r")
	for _, f := range queue {
		metrics := fmt.Sprintf("100%%   %8s  %9s/s    ", filesizeUnits(f.Filesize), filesizeUnits(bytesPerSec))
		name := formatFilename(f.Filename, termWidth-len(metrics)-4)

		buf := makeBuf(termWidth)
		copy(buf, []rune(name))
		copy(buf[len(buf)-len(metrics):], []rune(metrics))
		fmt.Printf("%s\n", string(buf))
	}
}
