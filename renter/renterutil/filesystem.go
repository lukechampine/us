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
	"gitlab.com/NebulousLabs/fastrand"
	"lukechampine.com/us/hostdb"
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

type openMetaFile struct {
	name          string
	m             renter.MetaIndex
	shards        [][]renter.SectorSlice
	pendingWrites []pendingWrite
	offset        int64
}

type pendingWrite struct {
	data       []byte
	offset     int64
	sliceIndex int // index within (SectorBuilder).Slices()
}

func (pw pendingWrite) end() int64 { return pw.offset + int64(len(pw.data)) }

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
// (before umask), truncating it if it already exists. The returned file only
// supports Write calls at the end of the file.
func (fs *PseudoFS) Create(name string, minShards int) (*PseudoFile, error) {
	return fs.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY|os.O_APPEND, 0666, minShards)
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

	var index renter.MetaIndex
	var shards [][]renter.SectorSlice
	if flag == os.O_CREATE|os.O_TRUNC|os.O_WRONLY|os.O_APPEND {
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

// Close closes the filesystem by flushing any uncommitted writes, closing any
// open files, and terminating all active host sessions.
func (fs *PseudoFS) Close() error {
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

func (fs *PseudoFS) commitChanges(f *openMetaFile) error {
	if !f.m.ModTime.After(fs.lastCommitTime) {
		return nil
	}

	// TODO: do this better
	contracts := make(renter.ContractSet)
	for hostKey := range fs.hosts.sessions {
		contracts[hostKey] = nil
	}
	os.RemoveAll("tmp-metafile")
	m, err := renter.NewMetaFile("tmp-metafile", f.m.Mode, f.m.Filesize, contracts, f.m.MinShards)
	if err != nil {
		return err
	}
	m.MetaIndex = f.m
	for i, hostKey := range m.Hosts {
		sf, err := renter.OpenShard(m.ShardPath(hostKey))
		if err != nil {
			return err
		}
		for chunkIndex, ss := range f.shards[i] {
			if err := sf.WriteSlice(ss, int64(chunkIndex)); err != nil {
				sf.Close()
				return err
			}
		}
		sf.Close()
	}
	if err := m.Close(); err != nil {
		return err
	}
	if err := os.Rename("tmp-metafile", fs.path(f.name)+metafileExt); err != nil {
		return err
	}
	return nil
}

// flushSectors uploads any non-empty sectors to their respective hosts, and
// updates any metafiles with pending changes.
func (fs *PseudoFS) flushSectors() error {
	// reset sectors
	for _, sb := range fs.sectors {
		sb.Reset()
	}

	// construct sectors by concatenating uncommitted writes in all files
	for _, f := range fs.files {
		if len(f.pendingWrites) == 0 {
			continue
		}

		shards := make([][]byte, len(f.m.Hosts))
		for i := range shards {
			shards[i] = make([]byte, 0, renterhost.SectorSize)
		}

		for i := range f.pendingWrites {
			pw := &f.pendingWrites[i]
			// if the write begins in the middle of a segment, we must download
			// that segment
			if align := pw.offset % f.m.MinChunkSize(); align != 0 {
				chunk := make([]byte, f.m.MinChunkSize())
				err := fs.readAt(f, chunk, pw.offset-align)
				if err != nil {
					return err
				}
				pw.offset -= align
				pw.data = append(chunk[:align], pw.data...)
			}
			// if the write ends in the middle of a segment, we must download
			// that segment
			pwEnd := pw.end()
			if align := pwEnd % f.m.MinChunkSize(); align != 0 && pwEnd < f.m.Filesize {
				chunk := make([]byte, f.m.MinChunkSize())
				err := fs.readAt(f, chunk, pwEnd-align)
				if err != nil {
					return err
				}
				pw.data = append(pw.data, chunk[f.m.MinChunkSize()-align:]...)
			}
			// encode the chunk
			f.m.ErasureCode().Encode(pw.data, shards)

			// append the shards to each sector
			for shardIndex, hostKey := range f.m.Hosts {
				fs.sectors[hostKey].Append(shards[shardIndex], f.m.MasterKey)
				pw.sliceIndex = len(fs.sectors[hostKey].Slices()) - 1
				// TODO: may need a separate sliceIndex for each sector...
			}
		}
	}

	// upload each sector
	for hostKey, sb := range fs.sectors {
		if sb.Len() == 0 {
			continue
		}
		sector := sb.Finish()
		h, err := fs.hosts.acquire(hostKey)
		if err != nil {
			return err
		}
		err = h.Write([]renterhost.RPCWriteAction{{
			Type: renterhost.RPCWriteActionAppend,
			Data: sector[:],
		}})
		fs.hosts.release(hostKey)
		if err != nil {
			return err
		}
	}

	// update files
	for _, f := range fs.files {
		fs.applyPendingWrites(f)
		if err := fs.commitChanges(f); err != nil {
			return err
		}
		f.pendingWrites = f.pendingWrites[:0]
	}

	fs.lastCommitTime = time.Now()
	return nil
}

func (fs *PseudoFS) applyPendingWrites(f *openMetaFile) {
	if len(f.pendingWrites) == 0 {
		return
	}

	newShards := make([][]renter.SectorSlice, len(f.shards))
	for i := range newShards {
		newShards[i] = f.shards[i][:0]
	}
	var offset int64
nextChunk:
	for chunkIndex := 0; chunkIndex < len(f.shards[0]); chunkIndex++ {
		oldEnd := offset + int64(f.shards[0][chunkIndex].NumSegments)*f.m.MinChunkSize()
		if oldEnd > f.m.Filesize {
			oldEnd = f.m.Filesize
		}

		for _, pw := range f.pendingWrites {
			pwEnd := pw.end()
			switch {
			// |  pending  |
			// |    old    |
			case pw.offset == offset && pwEnd == oldEnd:
				for shardIndex, hostKey := range f.m.Hosts {
					pending := fs.sectors[hostKey].Slices()[pw.sliceIndex]
					newShards[shardIndex] = append(newShards[shardIndex], pending)
				}
				offset = oldEnd
				continue nextChunk

			// | pending |
			// |    old    |
			case pw.offset == offset && pwEnd < oldEnd:
				for shardIndex, hostKey := range f.m.Hosts {
					old := f.shards[shardIndex][chunkIndex]
					old.SegmentIndex += uint32(int64(len(pw.data)) / merkle.SegmentSize)
					old.NumSegments -= uint32(int64(len(pw.data)) / merkle.SegmentSize)
					pending := fs.sectors[hostKey].Slices()[pw.sliceIndex]
					newShards[shardIndex] = append(newShards[shardIndex], old, pending)
				}
				offset = oldEnd
				continue nextChunk

			//   | pending |
			// |    old    |
			case offset < pw.offset && pwEnd == oldEnd:
				for shardIndex, hostKey := range f.m.Hosts {
					old := f.shards[shardIndex][chunkIndex]
					old.NumSegments -= uint32((pwEnd - pw.offset) / merkle.SegmentSize)
					pending := fs.sectors[hostKey].Slices()[pw.sliceIndex]
					newShards[shardIndex] = append(newShards[shardIndex], old, pending)
				}
				offset = oldEnd
				continue nextChunk

			//   |pending|
			// |    old    |
			case offset < pw.offset && pwEnd < oldEnd:
				for shardIndex, hostKey := range f.m.Hosts {
					old := f.shards[shardIndex][chunkIndex]
					oldLeft, oldRight := old, old // split old in two
					oldLeft.NumSegments -= uint32((oldEnd - pw.offset) / merkle.SegmentSize)
					oldRight.SegmentIndex += uint32((pwEnd - offset) / merkle.SegmentSize)
					oldRight.NumSegments -= uint32((pwEnd - offset) / merkle.SegmentSize)
					pending := fs.sectors[hostKey].Slices()[pw.sliceIndex]
					newShards[shardIndex] = append(newShards[shardIndex], oldLeft, pending, oldRight)
				}
				offset = oldEnd
				continue nextChunk

			//       |  pending  |
			// |    old    |    next    |
			case pw.offset < oldEnd && oldEnd < pwEnd:
				if chunkIndex == len(f.shards[0])-1 {
					// last SectorSlice
					for shardIndex, hostKey := range f.m.Hosts {
						old := f.shards[shardIndex][chunkIndex]
						old.NumSegments = uint32((pw.offset - offset) / f.m.MinChunkSize())
						pending := fs.sectors[hostKey].Slices()[pw.sliceIndex]
						if old.NumSegments > 0 {
							newShards[shardIndex] = append(newShards[shardIndex], old)
						}
						newShards[shardIndex] = append(newShards[shardIndex], pending)
					}
					offset = pwEnd
					continue nextChunk
				} else {
					for shardIndex, hostKey := range f.m.Hosts {
						old := f.shards[shardIndex][chunkIndex]
						next := f.shards[shardIndex][chunkIndex+1]
						old.NumSegments -= uint32((oldEnd - pw.offset) / merkle.SegmentSize)
						next.SegmentIndex += uint32((pwEnd - oldEnd) / merkle.SegmentSize)
						next.NumSegments -= uint32((pwEnd - oldEnd) / merkle.SegmentSize)
						pending := fs.sectors[hostKey].Slices()[pw.sliceIndex]
						newShards[shardIndex] = append(newShards[shardIndex], old, pending, next)
					}
					// skip next slice
					chunkIndex++
					offset = oldEnd + int64(f.shards[0][chunkIndex].NumSegments)*f.m.MinChunkSize()
					continue nextChunk
				}
			}
		}
		// no overlap with pending writes
		for j := range f.shards {
			newShards[j] = append(newShards[j], f.shards[j][chunkIndex])
		}
		offset = oldEnd
	}
	// add trailing writes
	for _, pw := range f.pendingWrites {
		if pw.offset == offset {
			for shardIndex, hostKey := range f.m.Hosts {
				pending := fs.sectors[hostKey].Slices()[pw.sliceIndex]
				newShards[shardIndex] = append(newShards[shardIndex], pending)
			}
			offset += int64(len(pw.data))
		}
	}
	f.shards = newShards
}

func (fs *PseudoFS) readAt(f *openMetaFile, p []byte, off int64) error {
	if off >= f.m.Filesize {
		return io.EOF
	}

	hosts := make([]*renter.ShardDownloader, len(f.m.Hosts))
	for i, hostKey := range f.m.Hosts {
		s, err := fs.hosts.acquire(hostKey)
		if err != nil {
			continue
		}
		defer fs.hosts.release(hostKey)
		hosts[i] = &renter.ShardDownloader{
			Downloader: s,
			Key:        f.m.MasterKey,
			Slices:     f.shards[i],
		}
	}
	start := (off / f.m.MinChunkSize()) * merkle.SegmentSize
	end := ((off + int64(len(p))) / f.m.MinChunkSize()) * merkle.SegmentSize
	if (off+int64(len(p)))%f.m.MinChunkSize() != 0 {
		end += merkle.SegmentSize
	}
	offset, length := start, end-start

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
			shards[i] = make([]byte, 0, renterhost.SectorSize)
		}
	}

	// recover data shards directly into p
	skip := int(off % f.m.MinChunkSize())
	w := &skipWriter{p, skip}
	err := f.m.ErasureCode().Recover(w, shards, skip+len(p))
	if err != nil {
		return errors.Wrap(err, "could not recover chunk")
	}

	// apply any pending writes
	//
	// TODO: do this *before* downloading, and only download what we don't have
	for _, pw := range f.pendingWrites {
		if off <= pw.offset && pw.offset <= off+int64(len(p)) {
			copy(p[pw.offset-off:], pw.data)
		} else if off <= pw.end() && pw.end() <= off+int64(len(p)) {
			copy(p, pw.data[off-pw.offset:])
		}
	}

	return nil
}

func (fs *PseudoFS) lookupFD(fd int) (file *openMetaFile, dir *os.File) {
	return fs.files[fd], fs.dirs[fd]
}

func (fs *PseudoFS) fdRead(fd int, p []byte) (int, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f, d := fs.lookupFD(fd)
	if f == nil && d == nil {
		return 0, errors.New("invalid file descriptor")
	} else if d != nil {
		return d.Read(p)
	}

	if f.offset >= f.m.Filesize {
		return 0, io.EOF
	} else if int64(len(p)) > f.m.Filesize-f.offset {
		// partial read at EOF
		p = p[:f.m.Filesize-f.offset]
	} else if int64(len(p)) > f.m.MaxChunkSize() {
		// never download more than SectorSize bytes from each host
		p = p[:f.m.MaxChunkSize()]
	}

	err := fs.readAt(f, p, f.offset)
	if err != nil {
		return 0, err
	}
	f.offset += int64(len(p))
	return len(p), err
}

func (f *openMetaFile) calcShardSize(offset int64, n int) int {
	shardSize := (n / int(f.m.MinChunkSize())) * merkle.SegmentSize
	// assume misaligned start and end
	// TODO: calculate precisely
	return shardSize + merkle.SegmentSize + merkle.SegmentSize
}

func (fs *PseudoFS) canFit(f *openMetaFile, shardSize int) bool {
	sectorSizes := make(map[hostdb.HostPublicKey]int)
	for _, of := range fs.files {
		for _, pw := range of.pendingWrites {
			shardSize := of.calcShardSize(pw.offset, len(pw.data))
			for _, hostKey := range of.m.Hosts {
				sectorSizes[hostKey] += shardSize
			}
		}
	}
	for _, hostKey := range f.m.Hosts {
		sectorSizes[hostKey] += shardSize
	}
	for _, size := range sectorSizes {
		if size > renterhost.SectorSize {
			return false
		}
	}
	return true
}

func (fs *PseudoFS) fdWrite(fd int, p []byte) (int, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f, d := fs.lookupFD(fd)
	if f == nil && d == nil {
		return 0, errors.New("invalid file descriptor")
	} else if d != nil {
		return d.Write(p)
	}

	if int64(len(p)) > f.m.MaxChunkSize() {
		// TODO: handle large writes
		return 0, errors.New("cannot handle writes larger than max chunk size")
	}

	// if appending p would overflow the uncommitted sectors, flush them to
	// hosts before continuing
	if !fs.canFit(f, f.calcShardSize(f.offset, len(p))) {
		if err := fs.flushSectors(); err != nil {
			return 0, err
		}
	}

	// merge this write with the other pending writes

	// seek to overlap
	var i int
	for i < len(f.pendingWrites) && f.pendingWrites[i].end() < f.offset {
		i++
	}
	newPending := f.pendingWrites[:i]

	pw := pendingWrite{
		data:   append([]byte(nil), p...),
		offset: f.offset,
	}
	// combine writes that overlap with pw into a single write; p overwrites
	// the data in existing writes
	for i < len(f.pendingWrites) && f.pendingWrites[i].offset < pw.end() {
		if w := f.pendingWrites[i]; w.offset < pw.offset {
			pw = pendingWrite{
				data:   append(w.data[:pw.offset-w.offset], pw.data...),
				offset: w.offset,
			}
		} else if w.end() > pw.end() {
			pw.data = append(pw.data, w.data[pw.end()-w.offset:]...)
		}
		i++
	}
	newPending = append(newPending, pw)

	// add later writes
	f.pendingWrites = append(newPending, f.pendingWrites[i:]...)

	// update metadata
	f.offset += int64(len(p))
	if f.offset > f.m.Filesize {
		f.m.Filesize = f.offset
	}
	f.m.ModTime = time.Now()

	return len(p), nil
}

func (fs *PseudoFS) fdSeek(fd int, offset int64, whence int) (int64, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f, d := fs.lookupFD(fd)
	if f == nil && d == nil {
		return 0, errors.New("invalid file descriptor")
	} else if d != nil {
		return d.Seek(offset, whence)
	}

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

func (fs *PseudoFS) fdReadAt(fd int, p []byte, off int64) (int, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f, d := fs.lookupFD(fd)
	if f == nil && d == nil {
		return 0, errors.New("invalid file descriptor")
	} else if d != nil {
		return d.ReadAt(p, off)
	}

	partial := false
	if off >= f.m.Filesize {
		return 0, io.EOF
	} else if off+int64(len(p)) > f.m.Filesize {
		p = p[:f.m.Filesize-off]
		partial = true
	}

	if err := fs.readAt(f, p, off); err != nil {
		return 0, err
	}
	if partial {
		return len(p), io.EOF
	}
	return len(p), nil
}

func (fs *PseudoFS) fdWriteAt(fd int, p []byte, off int64) (int, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f, d := fs.lookupFD(fd)
	if f == nil && d == nil {
		return 0, errors.New("invalid file descriptor")
	} else if d != nil {
		return d.WriteAt(p, off)
	}
	f.m.ModTime = time.Now()
	panic("unimplemented")
}

func (fs *PseudoFS) fdTruncate(fd int, size int64) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f, d := fs.lookupFD(fd)
	if f == nil && d == nil {
		return errors.New("invalid file descriptor")
	} else if d != nil {
		return d.Truncate(size)
	}

	f.m.Filesize = size

	// trim any pending writes
	newPending := f.pendingWrites[:0]
	for _, pw := range f.pendingWrites {
		if pw.offset >= f.m.Filesize {
			continue // remove
		} else if pw.offset+int64(len(pw.data)) > f.m.Filesize {
			pw.data = pw.data[:f.m.Filesize-pw.offset]
		}
		newPending = append(newPending, pw)
	}
	f.pendingWrites = newPending

	// update shards
	for shardIndex, slices := range f.shards {
		var n int64
		for i, s := range slices {
			sliceSize := int64(s.NumSegments) * f.m.MinChunkSize()
			if n+sliceSize > f.m.Filesize {
				// trim number of segments
				s.NumSegments -= uint32(n+sliceSize-f.m.Filesize) / uint32(f.m.MinChunkSize())
				if s.NumSegments == 0 {
					slices = slices[:i]
				} else {
					slices[i] = s
					slices = slices[:i+1]
				}
				break
			}
			n += sliceSize
		}
		f.shards[shardIndex] = slices
	}

	f.m.ModTime = time.Now()
	return nil
}

func (fs *PseudoFS) fdSync(fd int) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f, d := fs.lookupFD(fd)
	if f == nil && d == nil {
		return errors.New("invalid file descriptor")
	} else if d != nil {
		return d.Sync()
	}
	// TODO: only call flushSectors if the sectors contain data from this file
	return fs.flushSectors()
}

func (fs *PseudoFS) fdStat(fd int) (os.FileInfo, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f, d := fs.lookupFD(fd)
	if f == nil && d == nil {
		return nil, errors.New("invalid file descriptor")
	} else if d != nil {
		return d.Stat()
	}
	return pseudoFileInfo{name: f.name, m: f.m}, nil
}

func (fs *PseudoFS) fdClose(fd int) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f, d := fs.lookupFD(fd)
	if f == nil && d == nil {
		return errors.New("invalid file descriptor")
	} else if d != nil {
		delete(fs.dirs, fd)
		return d.Close()
	}
	// TODO: actually leave open if sectors are uncommitted
	if err := fs.flushSectors(); err != nil {
		return err
	}
	delete(fs.files, fd)
	return nil
}

func (fs *PseudoFS) fdReaddir(fd int, n int) ([]os.FileInfo, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f, d := fs.lookupFD(fd)
	if f == nil && d == nil {
		return nil, errors.New("invalid file descriptor")
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
	return files, err
}

func (fs *PseudoFS) fdReaddirnames(fd int, n int) ([]string, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f, d := fs.lookupFD(fd)
	if f == nil && d == nil {
		return nil, errors.New("invalid file descriptor")
	} else if d == nil {
		return nil, errors.New("not a directory")
	}
	return d.Readdirnames(n)
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

// Close implements io.Closer.
func (pf PseudoFile) Close() error { return pf.fs.fdClose(pf.fd) }

// Read implements io.Reader.
func (pf PseudoFile) Read(p []byte) (int, error) {
	if !pf.readable() {
		return 0, ErrNotReadable
	}
	return pf.fs.fdRead(pf.fd, p)
}

// Write implements io.Writer.
func (pf PseudoFile) Write(p []byte) (int, error) {
	if !pf.writeable() {
		return 0, ErrNotWriteable
	}
	return pf.fs.fdWrite(pf.fd, p)
}

// ReadAt implements io.ReaderAt.
func (pf PseudoFile) ReadAt(p []byte, off int64) (int, error) {
	if !pf.readable() {
		return 0, ErrNotReadable
	}
	return pf.fs.fdReadAt(pf.fd, p, off)
}

// WriteAt implements io.WriterAt.
func (pf PseudoFile) WriteAt(p []byte, off int64) (int, error) {
	if !pf.writeable() {
		return 0, ErrNotWriteable
	} else if pf.appendOnly() {
		return 0, ErrAppendOnly
	}
	return pf.fs.fdWriteAt(pf.fd, p, off)
}

// Seek implements io.Seeker.
func (pf PseudoFile) Seek(o int64, w int) (int64, error) {
	if pf.appendOnly() {
		return 0, ErrAppendOnly
	}
	return pf.fs.fdSeek(pf.fd, o, w)
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
func (pf PseudoFile) Readdir(n int) ([]os.FileInfo, error) { return pf.fs.fdReaddir(pf.fd, n) }

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
func (pf PseudoFile) Readdirnames(n int) ([]string, error) { return pf.fs.fdReaddirnames(pf.fd, n) }

// Stat returns the FileInfo structure describing the file. If the file is a
// metafile, its renter.MetaIndex will be available via the Sys method.
func (pf PseudoFile) Stat() (os.FileInfo, error) { return pf.fs.fdStat(pf.fd) }

// Sync commits the current contents of the file to stable storage. Any new data
// will be uploaded to hosts, and the metafile will be atomically updated to
// match the current state of the file. Calling Sync on one file may cause other
// files to be synced as well. Sync typically results in a full sector of data
// being uploaded to each host.
func (pf PseudoFile) Sync() error {
	if !pf.writeable() {
		return nil
	}
	return pf.fs.fdSync(pf.fd)
}

// Truncate changes the size of the file. It does not change the I/O offset. The
// new size must not exceed the current size.
func (pf PseudoFile) Truncate(size int64) error {
	if !pf.writeable() {
		return ErrNotWriteable
	}
	return pf.fs.fdTruncate(pf.fd, size)
}
