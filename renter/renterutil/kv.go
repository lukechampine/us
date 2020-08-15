package renterutil

import (
	"bytes"
	"io"

	"lukechampine.com/frand"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renterhost"
)

// PseudoKV implements a key-value store by uploading and downloading data from Sia
// hosts.
type PseudoKV struct {
	DB         MetaDB
	M, N, P    int
	Uploader   ChunkUploader
	Downloader ChunkDownloader
	Deleter    SectorDeleter
}

// Put uploads r to hosts and associates it with the specified key. Any existing
// data associated with the key will be overwritten.
func (kv PseudoKV) Put(key []byte, r io.Reader) error {
	b := DBBlob{Key: key}
	frand.Read(b.Seed[:])
	if err := kv.DB.AddBlob(b); err != nil {
		return err
	}
	bu := ParallelBlobUploader{
		U: kv.Uploader,
		M: kv.M,
		N: kv.N,
		P: kv.P,
	}
	return bu.UploadBlob(kv.DB, b, r)
}

// PutBytes uploads val to hosts and associates it with the specified key.
func (kv PseudoKV) PutBytes(key []byte, val []byte) error {
	return kv.Put(key, bytes.NewReader(val))
}

// Resume resumes uploading the value associated with key.
func (kv PseudoKV) Resume(key []byte, rs io.ReadSeeker) error {
	b, err := kv.DB.Blob(key)
	if err != nil {
		return err
	}
	// first repair any partially-uploaded chunks
	var offset uint64
	for _, cid := range b.Chunks {
		c, err := kv.DB.Chunk(cid)
		if err != nil {
			return err
		}
		for _, ssid := range c.Shards {
			if ssid == 0 {
				// TODO: only attempt repair if erasure params match
				if _, err := rs.Seek(int64(offset), io.SeekStart); err != nil {
					return err
				} else if err := kv.repairChunk(b, c, rs); err != nil {
					return err
				}
			}
		}
		offset += c.Len
	}
	if _, err := rs.Seek(int64(offset), io.SeekStart); err != nil {
		return err
	}

	bu := ParallelBlobUploader{
		U: kv.Uploader,
		M: kv.M,
		N: kv.N,
		P: kv.P,
	}
	return bu.UploadBlob(kv.DB, b, rs)
}

// GetRange downloads a range of bytes within the value associated with key and
// writes it to w.
func (kv PseudoKV) GetRange(key []byte, w io.Writer, off, n int64) error {
	b, err := kv.DB.Blob(key)
	if err != nil {
		return err
	}
	bd := ParallelBlobDownloader{
		D: kv.Downloader,
		P: kv.P,
	}
	return bd.DownloadBlob(kv.DB, b, w, off, n)
}

// Get downloads the value associated with key and writes it to w.
func (kv PseudoKV) Get(key []byte, w io.Writer) error {
	return kv.GetRange(key, w, 0, -1)
}

// GetBytes downloads the value associated with key and returns it as a []byte.
func (kv PseudoKV) GetBytes(key []byte) ([]byte, error) {
	var buf bytes.Buffer
	err := kv.Get(key, &buf)
	return buf.Bytes(), err
}

// Update updates an existing key, passing each of its chunks to bu.
func (kv *PseudoKV) Update(key []byte, bu BlobUpdater) error {
	b, err := kv.DB.Blob(key)
	if err != nil {
		return err
	}
	return bu.UpdateBlob(kv.DB, b)
}

// Migrate updates an existing key, migrating each each of its chunks to the
// provided HostSet.
func (kv *PseudoKV) Migrate(key []byte, hosts *HostSet) error {
	whitelist := make([]hostdb.HostPublicKey, 0, len(hosts.sessions))
	for hostKey := range hosts.sessions {
		whitelist = append(whitelist, hostKey)
	}
	return kv.Update(key, SerialBlobUpdater{
		U: GenericChunkUpdater{
			D:            kv.Downloader,
			U:            kv.Uploader,
			ShouldUpdate: NewMigrationWhitelist(whitelist),
			InPlace:      true,
		},
	})
}

// Delete deletes the value associated with key.
//
// The actual data stored on hosts is not deleted. To delete host data, use
// PseudoKV.GC.
func (kv PseudoKV) Delete(key []byte) error {
	return kv.DB.DeleteBlob(key)
}

// GC deletes from hosts all sectors that are not currently associated with any
// value.
func (kv PseudoKV) GC() error {
	sectors, err := kv.DB.UnreferencedSectors()
	if err != nil {
		return err
	}
	return kv.Deleter.DeleteSectors(kv.DB, sectors)
}

// Close implements io.Closer.
func (kv *PseudoKV) Close() error {
	return kv.DB.Close()
}

func (kv PseudoKV) repairChunk(b DBBlob, c DBChunk, r io.Reader) error {
	buf := make([]byte, c.Len)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	rsc := renter.NewRSCode(kv.M, kv.N)
	shards := make([][]byte, kv.N)
	for i := range shards {
		shards[i] = make([]byte, renterhost.SectorSize)
	}
	rsc.Encode(buf, shards)
	if err := kv.Uploader.UploadChunk(kv.DB, c, b.DeriveKey(c.ID), shards); err != nil {
		return err
	}
	return nil
}
