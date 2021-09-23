package renterutil

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"go.sia.tech/siad/crypto"
	"lukechampine.com/frand"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renterhost"
)

type openMetaFile struct {
	name          string
	m             *renter.MetaFile
	pendingWrites []pendingWrite
	pendingChunks []pendingChunk
	offset        int64
	closed        bool
}

type pendingWrite struct {
	data   []byte
	offset int64
}

func (pw pendingWrite) end() int64 { return pw.offset + int64(len(pw.data)) }

type pendingChunk struct {
	offset     int64 // in segments
	length     int64 // in segments
	sliceIndex int   // index within (SectorBuilder).Slices()
}

func mergePendingWrites(pendingWrites []pendingWrite, pw pendingWrite) []pendingWrite {
	// seek to overlap
	var i int
	for i < len(pendingWrites) && pendingWrites[i].end() < pw.offset {
		i++
	}
	newPending := pendingWrites[:i]

	// combine writes that overlap with pw into a single write; pw.data
	// overwrites the data in existing writes
	for i < len(pendingWrites) && pendingWrites[i].offset < pw.end() {
		if w := pendingWrites[i]; w.offset < pw.offset {
			// this should only happen once
			pw = pendingWrite{
				data:   append(w.data[:pw.offset-w.offset], pw.data...),
				offset: w.offset,
			}
			if w.end() > pw.end() {
				pw.data = pw.data[:len(w.data)]
			}
		} else if w.end() > pw.end() {
			pw.data = append(pw.data, w.data[pw.end()-w.offset:]...)
		}
		i++
	}
	newPending = append(newPending, pw)

	// add later writes
	return append(newPending, pendingWrites[i:]...)
}

func (f *openMetaFile) filesize() int64 {
	size := f.m.Filesize
	for _, pw := range f.pendingWrites {
		if pw.end() > size {
			size = pw.end()
		}
	}
	return size
}

func (f *openMetaFile) calcShardSize(offset int64, n int64) int64 {
	numSegments := n / f.m.MinChunkSize()
	if offset%f.m.MinChunkSize() != 0 {
		numSegments++
	}
	if (offset+n)%f.m.MinChunkSize() != 0 {
		numSegments++
	}
	return numSegments * merkle.SegmentSize
}

// use f.pendingChunks to lookup new slices for each shard, and overwrite f's
// shards with these
func (f *openMetaFile) commitPendingSlices(sectors map[hostdb.HostPublicKey]*renter.SectorBuilder) {
	if len(f.pendingChunks) == 0 {
		return
	}

	oldShards := f.m.Shards
	newShards := make([][]renter.SectorSlice, len(oldShards))
	for i := range newShards {
		newShards[i] = oldShards[i][:0]
	}
	pending := f.pendingChunks
	var offset int64
	for len(oldShards[0])+len(pending) > 0 {
		// mergesort-style merging of old and new slices, consuming from
		// whichever has priority
		switch {
		// consume a pending chunk
		case len(pending) > 0 && pending[0].offset == offset:
			pc := pending[0]
			pending = pending[1:]
			for i, hostKey := range f.m.Hosts {
				ss := sectors[hostKey].Slices()[pc.sliceIndex]
				newShards[i] = append(newShards[i], ss)
			}
			offset += pc.length
			// consume old slices that we overwrote
			overlap := pc.length
			for len(oldShards[0]) > 0 && overlap > 0 {
				ss := oldShards[0][0]
				if int64(ss.NumSegments) <= overlap {
					for i := range oldShards {
						oldShards[i] = oldShards[i][1:]
					}
					overlap -= int64(ss.NumSegments)
				} else {
					// trim the beginning of this chunk
					delta := ss.NumSegments - uint32(overlap)
					for i := range oldShards {
						oldShards[i][0].SegmentIndex += delta
						oldShards[i][0].NumSegments -= delta
					}
					break
				}
			}

		// consume an old slice
		case len(oldShards[0]) > 0:
			numSegments := int64(oldShards[0][0].NumSegments)
			for i := range oldShards {
				newShards[i] = append(newShards[i], oldShards[i][0])
				oldShards[i] = oldShards[i][1:]
			}
			// truncate if we would overlap a pending chunk
			if len(pending) > 0 && offset+numSegments > pending[0].offset {
				numSegments = pending[0].offset - offset
				for i := range newShards {
					newShards[i][len(newShards[i])-1].NumSegments = uint32(numSegments)
				}
			}
			offset += numSegments

		default:
			panic("developer error: cannot make progress")
		}
	}

	f.m.Shards = newShards
	f.m.Filesize = f.filesize()
}

func (fs *PseudoFS) commitChanges(f *openMetaFile) error {
	if !f.m.ModTime.After(fs.lastCommitTime) {
		return nil
	}
	return renter.WriteMetaFile(fs.path(f.name)+metafileExt, f.m)
}

// fill shared sectors with encoded chunks from pending writes; creates
// pendingChunks from pendingWrites
func (fs *PseudoFS) fillSectors(f *openMetaFile) error {
	f.pendingChunks = nil
	if len(f.pendingWrites) == 0 {
		return nil
	}
	// sanity check: we should have all of the file's hosts
	var missingHostErrs HostErrorSet
	for _, hostKey := range f.m.Hosts {
		if _, ok := fs.sectors[hostKey]; !ok {
			missingHostErrs = append(missingHostErrs, &HostError{
				HostKey: hostKey,
				Err:     errors.New("not in filesystem's host set"),
			})
		}
	}
	if missingHostErrs != nil {
		return missingHostErrs
	}

	// prepare shards
	shards := make([][]byte, len(f.m.Hosts))

	// extend each pendingWrite with its unaligned segments, merging writes as appropriate
	for i := 0; i < len(f.pendingWrites); i++ {
		pw := f.pendingWrites[i]
		// if the write begins in the middle of a segment, we must download
		// that segment
		if align := pw.offset % f.m.MinChunkSize(); align != 0 {
			chunk := make([]byte, f.m.MinChunkSize())
			_, err := fs.fileReadAt(f, chunk, pw.offset-align)
			if err != nil && err != io.EOF {
				return err
			}
			pw.offset -= align
			pw.data = append(chunk[:align], pw.data...)
		}
		// if the write ends in the middle of a segment, we must download
		// that segment
		if align := pw.end() % f.m.MinChunkSize(); align != 0 && pw.end() < f.m.Filesize {
			chunk := make([]byte, f.m.MinChunkSize())
			_, err := fs.fileReadAt(f, chunk, pw.end()-align)
			if err != nil && err != io.EOF {
				return err
			}
			pw.data = append(pw.data, chunk[align:]...)
		}
		// merge with subsequent writes, if applicable
		for i+1 < len(f.pendingWrites) && pw.end() >= f.pendingWrites[i+1].offset {
			next := f.pendingWrites[i+1]
			if pw.end() >= next.end() {
				// full overwrite; only happens if both writes are within same MinChunk
				copy(pw.data[next.offset-pw.offset:], next.data)
			} else {
				pw.data = append(pw.data[:next.offset-pw.offset], next.data...)
			}
			i++
		}
		// encode the chunk
		for i, hostKey := range f.m.Hosts {
			// map lookup guaranteed to succeed by earlier check
			shards[i] = fs.sectors[hostKey].SliceForAppend()
		}
		f.m.ErasureCode().Encode(pw.data, shards)

		// append the shards to each sector
		pc := pendingChunk{
			offset: pw.offset / f.m.MinChunkSize(),
			length: int64(len(shards[0])),
		}
		for shardIndex, hostKey := range f.m.Hosts {
			pc.sliceIndex = fs.sectors[hostKey].Append(shards[shardIndex], f.m.MasterKey, renter.RandomNonce())
			// TODO: may need a separate sliceIndex for each sector...
		}
		f.pendingChunks = append(f.pendingChunks, pc)
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
		if err := fs.fillSectors(f); err != nil {
			return err
		}
	}

	// upload each sector in parallel
	errChan := make(chan *HostError)
	var numHosts int
	for hostKey, sb := range fs.sectors {
		if sb.Len() == 0 {
			continue
		}
		numHosts++
		go func(hostKey hostdb.HostPublicKey, sb *renter.SectorBuilder) {
			sector := sb.Finish()
			h, err := fs.hosts.acquire(hostKey)
			if err != nil {
				errChan <- &HostError{hostKey, err}
				return
			}
			root, err := h.Append(sector)
			fs.hosts.release(hostKey)
			if err != nil {
				errChan <- &HostError{hostKey, err}
				return
			}
			sb.SetMerkleRoot(root)
			errChan <- nil
		}(hostKey, sb)
	}
	var errs HostErrorSet
	for i := 0; i < numHosts; i++ {
		if err := <-errChan; err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return fmt.Errorf("could not upload to some hosts: %w", errs)
	}

	// update files
	for fd, f := range fs.files {
		f.commitPendingSlices(fs.sectors)
		if err := fs.commitChanges(f); err != nil {
			return err
		}
		f.pendingWrites = f.pendingWrites[:0]
		if f.closed {
			delete(fs.files, fd)
		}
	}
	fs.lastCommitTime = time.Now()
	return nil
}

func (fs *PseudoFS) fileRead(f *openMetaFile, p []byte) (int, error) {
	if size := f.filesize(); f.offset >= size {
		return 0, io.EOF
	} else if int64(len(p)) > size-f.offset {
		// partial read at EOF
		p = p[:size-f.offset]
	} else if int64(len(p)) > f.m.MaxChunkSize() {
		// never download more than SectorSize bytes from each host
		p = p[:f.m.MaxChunkSize()]
	}

	_, err := fs.fileReadAt(f, p, f.offset)
	if err != nil {
		return 0, err
	}
	f.offset += int64(len(p))
	return len(p), err
}

func (fs *PseudoFS) fileWrite(f *openMetaFile, p []byte) (int, error) {
	if _, err := fs.fileWriteAt(f, p, f.offset); err != nil {
		return 0, err
	}
	f.offset += int64(len(p))
	return len(p), nil
}

func (fs *PseudoFS) fileSeek(f *openMetaFile, offset int64, whence int) (int64, error) {
	newOffset := f.offset
	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset += offset
	case io.SeekEnd:
		newOffset = f.filesize() - offset
	}
	if newOffset < 0 {
		return 0, errors.New("seek position cannot be negative")
	}
	f.offset = newOffset
	return f.offset, nil
}

func (fs *PseudoFS) fileReadAt(f *openMetaFile, p []byte, off int64) (int, error) {
	lenp := len(p)
	partial := false
	if size := f.filesize(); off >= size {
		return 0, io.EOF
	} else if off+int64(len(p)) > size {
		p = p[:size-off]
		lenp = len(p)
		partial = true
	}

	// check for a pending write that fully overlaps p
	for _, pw := range f.pendingWrites {
		if pw.offset <= off && off+int64(len(p)) <= pw.end() {
			copy(p, pw.data[off-pw.offset:])
			return lenp, nil
		}
	}
	// check for a pending write that partially overlaps p at the end of the
	// file; we won't be able to download this data, since it hasn't been
	// uploaded to hosts yet
	if off+int64(len(p)) > f.m.Filesize {
		for _, pw := range f.pendingWrites {
			if pw.offset <= off+int64(len(p)) && off+int64(len(p)) <= pw.end() {
				copy(p[f.m.Filesize-off:], pw.data[f.m.Filesize-pw.offset:])
				p = p[:f.m.Filesize-off]
				break
			}
		}
	}

	start := (off / f.m.MinChunkSize()) * merkle.SegmentSize
	end := ((off + int64(len(p))) / f.m.MinChunkSize()) * merkle.SegmentSize
	if (off+int64(len(p)))%f.m.MinChunkSize() != 0 {
		end += merkle.SegmentSize
	}
	offset, length := start, end-start

	// download shards in parallel, stopping when we have any f.m.MinShards of
	// them
	shards := make([][]byte, len(f.m.Hosts))
	for i := range shards {
		shards[i] = make([]byte, 0, length)
	}
	type req struct {
		shardIndex int
		block      bool // wait to acquire
	}
	reqChan := make(chan req, f.m.MinShards)
	respChan := make(chan *HostError, f.m.MinShards)
	reqQueue := make([]req, len(f.m.Hosts))
	// initialize queue in random order
	for i, shardIndex := range frand.Perm(len(reqQueue)) {
		reqQueue[i] = req{shardIndex, false}
	}
	for len(reqQueue) > len(f.m.Hosts)-f.m.MinShards {
		go func() {
			for req := range reqChan {
				hostKey := f.m.Hosts[req.shardIndex]
				s, err := fs.hosts.tryAcquire(hostKey)
				if err == errHostAcquired && req.block {
					s, err = fs.hosts.acquire(hostKey)
				}
				if err != nil {
					respChan <- &HostError{hostKey, err}
					continue
				}
				buf := bytes.NewBuffer(shards[req.shardIndex])
				err = (&renter.ShardDownloader{
					Downloader: s,
					Key:        f.m.MasterKey,
					Slices:     f.m.Shards[req.shardIndex],
				}).CopySection(buf, offset, length)
				fs.hosts.release(hostKey)
				if err != nil {
					respChan <- &HostError{hostKey, err}
					continue
				}
				shards[req.shardIndex] = buf.Bytes()
				respChan <- nil
			}
		}()
		reqChan <- reqQueue[0]
		reqQueue = reqQueue[1:]
	}

	var goodShards int
	var errs HostErrorSet
	for goodShards < f.m.MinShards && goodShards+len(errs) < len(f.m.Hosts) {
		err := <-respChan
		if err == nil {
			goodShards++
		} else {
			if err.Err == errHostAcquired {
				// host could not be acquired without blocking; add it to the back
				// of the queue, but next time, block
				reqQueue = append(reqQueue, req{
					shardIndex: f.m.HostIndex(err.HostKey),
					block:      true,
				})
			} else {
				// downloading from this host failed; don't try it again
				errs = append(errs, err)
			}
			// try the next host in the queue
			if len(reqQueue) > 0 {
				reqChan <- reqQueue[0]
				reqQueue = reqQueue[1:]
			}
		}
	}
	close(reqChan)
	if goodShards < f.m.MinShards {
		return 0, fmt.Errorf("too many hosts did not supply their shard (needed %v, got %v): %w",
			f.m.MinShards, goodShards, errs)
	}

	// recover data shards directly into p
	skip := int(off % f.m.MinChunkSize())
	err := f.m.ErasureCode().Recover(bytes.NewBuffer(p[:0]), shards, skip, len(p))
	if err != nil {
		return 0, fmt.Errorf("could not recover chunk: %w", err)
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

	if partial {
		return lenp, io.EOF
	}
	return lenp, nil
}

func (fs *PseudoFS) maxWriteSize(f *openMetaFile, off int64, n int64) int64 {
	sectorSizes := make(map[hostdb.HostPublicKey]int64)
	for _, of := range fs.files {
		for _, pw := range of.pendingWrites {
			shardSize := of.calcShardSize(pw.offset, int64(len(pw.data)))
			for _, hostKey := range of.m.Hosts {
				sectorSizes[hostKey] += shardSize
			}
		}
	}
	var maxRem int64
	for _, hostKey := range f.m.Hosts {
		if rem := renterhost.SectorSize - sectorSizes[hostKey]; rem > maxRem {
			maxRem = rem
		}
	}
	maxSegs := maxRem / f.m.MinChunkSize()
	if maxSegs > 0 && off%f.m.MinChunkSize() != 0 {
		maxSegs--
	}
	if maxSegs > 0 && (off+maxRem)%f.m.MinChunkSize() != 0 {
		maxSegs--
	}
	if maxWrite := maxSegs * merkle.SegmentSize; n > maxWrite {
		n = maxWrite
	}
	return n
}

func (fs *PseudoFS) fileWriteAt(f *openMetaFile, p []byte, off int64) (int, error) {
	lenp := len(p)
	for len(p) > 0 {
		if n := fs.maxWriteSize(f, off, int64(len(p))); n <= 0 {
			if err := fs.flushSectors(); err != nil {
				return 0, err
			}
		} else {
			f.pendingWrites = mergePendingWrites(f.pendingWrites, pendingWrite{
				data:   append([]byte(nil), p[:n]...),
				offset: off,
			})
			p = p[n:]
			off += n
		}
	}
	f.m.ModTime = time.Now()
	return lenp, nil
}

func (fs *PseudoFS) fileTruncate(f *openMetaFile, size int64) error {
	if size > f.filesize() {
		zeros := make([]byte, size-f.filesize())
		_, err := fs.fileWriteAt(f, zeros, f.filesize())
		return err
	}

	// trim any pending writes
	newPending := f.pendingWrites[:0]
	for _, pw := range f.pendingWrites {
		if pw.offset >= size {
			continue // remove
		} else if pw.offset+int64(len(pw.data)) > size {
			pw.data = pw.data[:size-pw.offset]
		}
		newPending = append(newPending, pw)
	}
	f.pendingWrites = newPending

	if size < f.m.Filesize {
		f.m.Filesize = size
		// update shards
		for shardIndex, slices := range f.m.Shards {
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
			f.m.Shards[shardIndex] = slices
		}
	}

	f.m.ModTime = time.Now()
	return fs.flushSectors() // TODO: avoid this
}

func (fs *PseudoFS) fileFree(f *openMetaFile) error {
	// discard pending writes
	f.pendingWrites = f.pendingWrites[:0]
	f.pendingChunks = f.pendingChunks[:0]

	// delete from each host
	//
	// TODO: parallelize
	for shardIndex, hostKey := range f.m.Hosts {
		shard := f.m.Shards[shardIndex]
		err := func() error {
			h, err := fs.hosts.acquire(hostKey)
			if err != nil {
				return err
			}
			defer fs.hosts.release(hostKey)
			var roots []crypto.Hash
			for _, ss := range shard {
				if ss.NumSegments == merkle.SegmentsPerSector {
					roots = append(roots, ss.MerkleRoot)
				}
			}
			if err := h.DeleteSectors(roots); err != nil {
				return err
			}
			return nil
		}()
		if err != nil {
			return err
		}
		// delete the shard
		f.m.Shards[shardIndex] = nil
	}

	f.m.Filesize = 0
	f.offset = 0
	f.m.ModTime = time.Now()
	return nil
}

func (fs *PseudoFS) fileSync(f *openMetaFile) error {
	if len(f.pendingWrites) > 0 {
		return fs.flushSectors()
	}
	return nil
}

func (fs *PseudoFS) fileStat(f *openMetaFile) (os.FileInfo, error) {
	info := pseudoFileInfo{name: f.name, m: f.m.MetaIndex}
	info.m.Filesize = f.filesize()
	return info, nil
}
