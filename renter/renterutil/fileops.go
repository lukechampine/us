package renterutil

import (
	"bytes"
	"io"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renterhost"
)

// helper type that skips a prefix of the bytes written to it; used to trim
// chunks during erasure decoding
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

type openMetaFile struct {
	name          string
	m             renter.MetaIndex
	shards        [][]renter.SectorSlice
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

func (f *openMetaFile) calcShardSize(offset int64, n int) int {
	numSegments := n / int(f.m.MinChunkSize())
	if offset%f.m.MinChunkSize() != 0 {
		numSegments++
	}
	if (offset+int64(n))%f.m.MinChunkSize() != 0 {
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

	newShards := make([][]renter.SectorSlice, len(f.shards))
	oldShards := f.shards
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
		}
	}

	f.shards = newShards
	f.m.Filesize = f.filesize()
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

// fill shared sectors with encoded chunks from pending writes; creates
// pendingChunks from pendingWrites
func (fs *PseudoFS) fillSectors(f *openMetaFile) error {
	f.pendingChunks = nil
	if len(f.pendingWrites) == 0 {
		return nil
	}

	shards := make([][]byte, len(f.m.Hosts))
	for i := range shards {
		shards[i] = make([]byte, 0, renterhost.SectorSize)
	}

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
		f.m.ErasureCode().Encode(pw.data, shards)

		// append the shards to each sector
		pc := pendingChunk{
			offset: pw.offset / f.m.MinChunkSize(),
			length: int64(len(shards[0])),
		}
		for shardIndex, hostKey := range f.m.Hosts {
			fs.sectors[hostKey].Append(shards[shardIndex], f.m.MasterKey)
			pc.sliceIndex = len(fs.sectors[hostKey].Slices()) - 1
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
	errChan := make(chan error)
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
				errChan <- err
				return
			}
			err = h.Write([]renterhost.RPCWriteAction{{
				Type: renterhost.RPCWriteActionAppend,
				Data: sector[:],
			}})
			fs.hosts.release(hostKey)
			if err != nil {
				errChan <- err
				return
			}
			errChan <- nil
		}(hostKey, sb)
	}
	var errStrings []string
	for i := 0; i < numHosts; i++ {
		if err := <-errChan; err != nil {
			errStrings = append(errStrings, err.Error())
		}
	}
	if len(errStrings) != 0 {
		return errors.New("could not upload to some hosts:\n" + strings.Join(errStrings, "\n"))
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
	// check a pending write that partially overlaps p at the end of the file;
	// we won't be able to download this data, since it hasn't been uploaded to
	// hosts yet
	if off+int64(len(p)) > f.m.Filesize {
		for _, pw := range f.pendingWrites {
			if pw.offset <= off+int64(len(p)) && off+int64(len(p)) <= pw.end() {
				copy(p[f.m.Filesize-off:], pw.data[f.m.Filesize-pw.offset:])
				p = p[:f.m.Filesize-off]
				break
			}
		}
	}

	hosts := make([]*renter.ShardDownloader, len(f.m.Hosts))
	var nHosts int
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
		nHosts++
	}
	if nHosts < f.m.MinShards {
		return 0, errors.Errorf("insufficient hosts to recover file data (needed %v, got %v)", f.m.MinShards, nHosts)
	}

	start := (off / f.m.MinChunkSize()) * merkle.SegmentSize
	end := ((off + int64(len(p))) / f.m.MinChunkSize()) * merkle.SegmentSize
	if (off+int64(len(p)))%f.m.MinChunkSize() != 0 {
		end += merkle.SegmentSize
	}
	offset, length := start, end-start

	// download shards in parallel, stopping when we have any f.m.MinShards of
	// them
	shards := make([][]byte, len(hosts))
	reqChan := make(chan int, f.m.MinShards)
	respChan := make(chan error, f.m.MinShards)
	var reqIndex int
	for ; reqIndex < f.m.MinShards; reqIndex++ {
		go func() {
			for shardIndex := range reqChan {
				var buf bytes.Buffer
				err := hosts[shardIndex].CopySection(&buf, offset, length)
				if err == nil {
					shards[shardIndex] = buf.Bytes()
				}
				respChan <- err
			}
		}()
		reqChan <- reqIndex
	}
	var goodShards int
	var errStrings []string
	for goodShards < f.m.MinShards && goodShards+len(errStrings) < len(hosts) {
		err := <-respChan
		if err == nil {
			goodShards++
		} else {
			errStrings = append(errStrings, err.Error())
			if reqIndex < len(hosts) {
				reqChan <- reqIndex
				reqIndex++
			}
		}
	}
	close(reqChan)
	if goodShards < f.m.MinShards {
		return 0, errors.New("too many hosts did not supply their shard:\n" + strings.Join(errStrings, "\n"))
	}

	// recover data shards directly into p
	for i := range shards {
		if len(shards[i]) == 0 {
			shards[i] = make([]byte, 0, length)
		}
	}
	skip := int(off % f.m.MinChunkSize())
	w := &skipWriter{p, skip}
	err := f.m.ErasureCode().Recover(w, shards, skip+len(p))
	if err != nil {
		return 0, errors.Wrap(err, "could not recover chunk")
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

func (fs *PseudoFS) fileWriteAt(f *openMetaFile, p []byte, off int64) (int, error) {
	lenp := len(p)
	for int64(len(p)) > f.m.MaxChunkSize() {
		if _, err := fs.fileWriteAt(f, p[:f.m.MaxChunkSize()], off); err != nil {
			return 0, err
		}
		p = p[f.m.MaxChunkSize():]
		off += f.m.MaxChunkSize()
	}

	// TODO: we use the same overflow calculation as Write, which is wasteful;
	// if we overwrite another pendingWrite, we might not overflow.
	if shardSize := f.calcShardSize(off, len(p)); !fs.canFit(f, shardSize) {
		if err := fs.flushSectors(); err != nil {
			return 0, err
		}
	}

	// merge this write with the other pending writes
	f.pendingWrites = mergePendingWrites(f.pendingWrites, pendingWrite{
		data:   append([]byte(nil), p...),
		offset: off,
	})

	// update metadata
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
	}

	f.m.ModTime = time.Now()
	return fs.flushSectors() // TODO: avoid this
}

func (fs *PseudoFS) fileSync(f *openMetaFile) error {
	if len(f.pendingWrites) > 0 {
		return fs.flushSectors()
	}
	return nil
}

func (fs *PseudoFS) fileStat(f *openMetaFile) (os.FileInfo, error) {
	info := pseudoFileInfo{name: f.name, m: f.m}
	info.m.Filesize = f.filesize()
	return info, nil
}
