package renterutil

import (
	"io"
	"time"

	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renterhost"
)

func replaceHosts(oldHosts []hostdb.HostPublicKey, hs *HostSet) []hostdb.HostPublicKey {
	isOld := func(h hostdb.HostPublicKey) bool {
		for i := range oldHosts {
			if oldHosts[i] == h {
				return true
			}
		}
		return false
	}

	r := append([]hostdb.HostPublicKey(nil), oldHosts...)
	for host := range hs.sessions {
		if !isOld(host) {
			for i := range r {
				if !hs.HasHost(r[i]) {
					r[i] = host
					break
				}
			}
		}
	}
	return r
}

// A Migrator facilitates migrating metafiles from one set of hosts to another.
type Migrator struct {
	hosts   *HostSet
	shards  map[hostdb.HostPublicKey]*renter.SectorBuilder
	onFlush []func() error
}

func (m *Migrator) canFit(shardLen int, oldHosts, newHosts []hostdb.HostPublicKey) bool {
	for i := range newHosts {
		if oldHosts[i] == newHosts[i] {
			continue // not uploading to this host
		}
		if m.shards[newHosts[i]].Remaining() < shardLen {
			return false
		}
	}
	return true
}

// NeedsMigrate returns true if at least one of the hosts of f is not present in
// the Migrator's HostSet.
func (m *Migrator) NeedsMigrate(f *renter.MetaFile) bool {
	newHosts := replaceHosts(f.Hosts, m.hosts)
	for i := range newHosts {
		if newHosts[i] != f.Hosts[i] {
			return true
		}
	}
	return false
}

// AddFile uses data read from source to migrate f to the Migrator's new host
// set. Since the Migrator buffers data internally, the migration may not be
// complete until the Flush method has been called. onFinish is called on the
// new metafile when the file has been fully migrated.
func (m *Migrator) AddFile(f *renter.MetaFile, source io.Reader, onFinish func(*renter.MetaFile) error) error {
	newHosts := replaceHosts(f.Hosts, m.hosts)
	newShards := make([][]renter.SectorSlice, len(newHosts))

	chunk := make([]byte, f.MaxChunkSize())
	shards := make([][]byte, len(f.Hosts))
	for i := range shards {
		shards[i] = make([]byte, 0, renterhost.SectorSize)
	}

	for _, ss := range f.Shards[0] {
		// read next chunk
		chunkSize := int(ss.NumSegments*merkle.SegmentSize) * f.MinShards
		n, err := io.ReadFull(source, chunk[:chunkSize])
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		} else if n == 0 {
			break // done
		}
		// erasure-encode
		f.ErasureCode().Encode(chunk[:n], shards)
		// make room if necessary
		if !m.canFit(len(shards[0]), f.Hosts, newHosts) {
			if err := m.Flush(); err != nil {
				return err
			}
		}
		// append to sector builders
		sliceIndices := make([]int, len(newHosts))
		for i, hostKey := range newHosts {
			if hostKey == f.Hosts[i] {
				continue // no migration necessary
			}
			s := m.shards[hostKey]
			s.Append(shards[i], f.MasterKey)
			sliceIndices[i] = len(s.Slices()) - 1
		}
		// append to newShards when this sector is flushed (which should be on
		// the next iteration, unless we've reached the end of the file)
		m.onFlush = append(m.onFlush, func() error {
			for i := range newShards {
				if newHosts[i] != f.Hosts[i] {
					s := m.shards[newHosts[i]]
					sliceIndex := sliceIndices[i]
					newShards[i] = append(newShards[i], s.Slices()[sliceIndex])
				}
			}
			return nil
		})
	}
	m.onFlush = append(m.onFlush, func() error {
		for i := range f.Shards {
			if newHosts[i] != f.Hosts[i] {
				f.Shards[i] = newShards[i]
			}
		}
		f.Hosts = newHosts
		f.ModTime = time.Now()
		return onFinish(f)
	})
	return nil
}

// Flush flushes any un-uploaded migration data to the new hosts. Flush must be
// called to guarantee that migration is complete.
func (m *Migrator) Flush() error {
	for hostKey, s := range m.shards {
		if s.Len() == 0 {
			continue
		}
		h, err := m.hosts.acquire(hostKey)
		if err != nil {
			return err
		}
		sector := s.Finish()
		err = h.Write([]renterhost.RPCWriteAction{{
			Type: renterhost.RPCWriteActionAppend,
			Data: sector[:],
		}})
		m.hosts.release(hostKey)
		if err != nil {
			return err
		}
	}

	for _, fn := range m.onFlush {
		if err := fn(); err != nil {
			return err
		}
	}
	m.onFlush = m.onFlush[:0]

	for _, s := range m.shards {
		s.Reset()
	}

	return nil
}

// NewMigrator creates a Migrator that migrates files to the specified host set.
func NewMigrator(hosts *HostSet) *Migrator {
	shards := make(map[hostdb.HostPublicKey]*renter.SectorBuilder)
	for hostKey := range hosts.sessions {
		shards[hostKey] = new(renter.SectorBuilder)
	}
	return &Migrator{
		hosts:  hosts,
		shards: shards,
	}
}
