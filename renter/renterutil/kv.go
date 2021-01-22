package renterutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

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
func (kv PseudoKV) Put(ctx context.Context, key []byte, r io.Reader) error {
	b := DBBlob{Key: key}
	frand.Read(b.Seed[:])
	if err := kv.DB.AddBlob(b); err != nil {
		return err
	}
	var bu BlobUploader
	if kv.P == 1 {
		bu = SerialBlobUploader{
			U: kv.Uploader,
			M: kv.M,
			N: kv.N,
		}
	} else {
		bu = ParallelBlobUploader{
			U: kv.Uploader,
			M: kv.M,
			N: kv.N,
			P: kv.P,
		}
	}
	return bu.UploadBlob(ctx, kv.DB, b, r)
}

// PutBytes uploads val to hosts and associates it with the specified key.
func (kv PseudoKV) PutBytes(ctx context.Context, key []byte, val []byte) error {
	return kv.Put(ctx, key, bytes.NewReader(val))
}

// Resume resumes uploading the value associated with key.
func (kv PseudoKV) Resume(ctx context.Context, key []byte, rs io.ReadSeeker) error {
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
				} else if err := kv.repairChunk(ctx, b, c, rs); err != nil {
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
	return bu.UploadBlob(ctx, kv.DB, b, rs)
}

// GetRange downloads a range of bytes within the value associated with key and
// writes it to w.
func (kv PseudoKV) GetRange(ctx context.Context, key []byte, w io.Writer, off, n int64) error {
	b, err := kv.DB.Blob(key)
	if err != nil {
		return err
	}
	bd := ParallelBlobDownloader{
		D: kv.Downloader,
		P: kv.P,
	}
	return bd.DownloadBlob(ctx, kv.DB, b, w, off, n)
}

// Get downloads the value associated with key and writes it to w.
func (kv PseudoKV) Get(ctx context.Context, key []byte, w io.Writer) error {
	return kv.GetRange(ctx, key, w, 0, -1)
}

// GetBytes downloads the value associated with key and returns it as a []byte.
func (kv PseudoKV) GetBytes(ctx context.Context, key []byte) ([]byte, error) {
	var buf bytes.Buffer
	err := kv.Get(ctx, key, &buf)
	return buf.Bytes(), err
}

// Update updates an existing key, passing each of its chunks to bu.
func (kv *PseudoKV) Update(ctx context.Context, key []byte, bu BlobUpdater) error {
	b, err := kv.DB.Blob(key)
	if err != nil {
		return err
	}
	return bu.UpdateBlob(ctx, kv.DB, b)
}

// Migrate updates an existing key, migrating each each of its chunks to the
// provided HostSet.
func (kv *PseudoKV) Migrate(ctx context.Context, key []byte, hosts *HostSet) error {
	whitelist := make([]hostdb.HostPublicKey, 0, len(hosts.sessions))
	for hostKey := range hosts.sessions {
		whitelist = append(whitelist, hostKey)
	}
	return kv.Update(ctx, key, SerialBlobUpdater{
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
func (kv PseudoKV) GC(ctx context.Context) error {
	sectors, err := kv.DB.UnreferencedSectors()
	if err != nil {
		return err
	}
	return kv.Deleter.DeleteSectors(ctx, kv.DB, sectors)
}

// Close implements io.Closer.
func (kv *PseudoKV) Close() error {
	return kv.DB.Close()
}

func (kv PseudoKV) repairChunk(ctx context.Context, b DBBlob, c DBChunk, r io.Reader) error {
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
	if err := kv.Uploader.UploadChunk(ctx, kv.DB, c, b.Seed, shards); err != nil {
		return err
	}
	return nil
}

// A SmallBlobBuffer packs multiple blobs into one sector (per host) for
// simultaneous upload.
type SmallBlobBuffer struct {
	kv     PseudoKV
	shards []renter.SectorBuilder
	blobs  []DBBlob
	lens   []int
}

// Remaining is the number of bytes that can be added to the buffer. Calling
// AddBlob with a value exceeding this size will result in a panic.
func (sbb *SmallBlobBuffer) Remaining() int {
	return sbb.kv.M * sbb.shards[0].Remaining()
}

// AddBlob adds a key-value pair to the buffer. It panics if the value is too
// large to fit in the buffer.
func (sbb *SmallBlobBuffer) AddBlob(key []byte, val []byte) {
	shards := make([][]byte, len(sbb.shards))
	for i := range shards {
		shards[i] = sbb.shards[i].SliceForAppend()
	}
	renter.NewRSCode(sbb.kv.M, sbb.kv.N).Encode(val, shards)
	seed := frand.Entropy256()
	for i := range shards {
		sbb.shards[i].Append(shards[i], seed, renter.RandomNonce())
	}
	sbb.blobs = append(sbb.blobs, DBBlob{
		Key:  key,
		Seed: seed,
	})
	sbb.lens = append(sbb.lens, len(val))
}

// NewSmallBlobBuffer initializes a SmallBlobBuffer backed by kv.
func (kv PseudoKV) NewSmallBlobBuffer() *SmallBlobBuffer {
	return &SmallBlobBuffer{
		kv:     kv,
		shards: make([]renter.SectorBuilder, kv.N),
	}
}

// Upload uploads all blobs in the buffer and adds them to the KV.
func (sbb *SmallBlobBuffer) Upload(ctx context.Context, hosts *HostSet) error {
	if len(sbb.shards) > len(hosts.sessions) {
		return errors.New("more shards than hosts")
	}
	// choose hosts
	newHosts := make(map[hostdb.HostPublicKey]struct{})
	for h := range hosts.sessions {
		newHosts[h] = struct{}{}
	}
	chooseHost := func() (h hostdb.HostPublicKey) {
		for h = range newHosts {
			delete(newHosts, h)
			break
		}
		return
	}
	rem := len(sbb.shards)

	// spawn workers
	type req struct {
		shardIndex int
		hostKey    hostdb.HostPublicKey
		shard      *[renterhost.SectorSize]byte
		block      bool // wait to acquire
	}
	type resp struct {
		req req
		err error
	}
	reqChan := make(chan req, rem)
	respChan := make(chan resp, rem)
	var wg sync.WaitGroup
	defer wg.Wait()
	for i := 0; i < rem; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range reqChan {
				sess, err := hosts.tryAcquire(req.hostKey)
				if err == errHostAcquired && req.block {
					sess, err = hosts.acquire(req.hostKey)
				}
				if err != nil {
					respChan <- resp{req, err}
					continue
				}

				root, err := uploadCtx(ctx, sess, req.shard)
				hosts.release(req.hostKey)
				if err != nil {
					respChan <- resp{req, err}
					continue
				}
				sbb.shards[req.shardIndex].SetMerkleRoot(root)
				respChan <- resp{req, nil}
			}
		}()
	}

	// start by requesting uploads to rem hosts, non-blocking.
	var inflight int
	for shardIndex := range sbb.shards {
		reqChan <- req{
			shardIndex: shardIndex,
			hostKey:    chooseHost(),
			shard:      sbb.shards[shardIndex].Finish(),
			block:      false,
		}
		inflight++
	}

	// for those that return errors, add the next host to the queue, non-blocking.
	// for those that block, add the same host to the queue, blocking.
	var reqQueue []req
	var errs HostErrorSet
	finalHosts := make([]hostdb.HostPublicKey, len(sbb.shards))
	for inflight > 0 {
		resp := <-respChan
		inflight--
		if resp.err == nil {
			finalHosts[resp.req.shardIndex] = resp.req.hostKey
			rem--
		} else {
			if resp.err == errHostAcquired {
				// host could not be acquired without blocking; add it to the back
				// of the queue, but next time, block
				resp.req.block = true
				reqQueue = append(reqQueue, resp.req)
			} else {
				// uploading to this host failed; don't try it again
				errs = append(errs, &HostError{resp.req.hostKey, resp.err})
				// add a different host to the queue, if able
				if len(newHosts) > 0 {
					resp.req.hostKey = chooseHost()
					resp.req.block = false
					reqQueue = append(reqQueue, resp.req)
				}
			}
			// try the next host in the queue
			if len(reqQueue) > 0 {
				reqChan <- reqQueue[0]
				reqQueue = reqQueue[1:]
				inflight++
			}
		}
	}
	close(reqChan)
	if rem > 0 {
		return fmt.Errorf("could not upload to enough hosts: %w", errs)
	}

	// insert all blobs into db
	for blobIndex, blob := range sbb.blobs {
		c, err := sbb.kv.DB.AddChunk(sbb.kv.M, sbb.kv.N, uint64(sbb.lens[blobIndex]))
		if err != nil {
			return err
		}
		for shardIndex := range sbb.shards {
			ss := sbb.shards[shardIndex].Slices()[blobIndex]
			if sid, err := sbb.kv.DB.AddShard(DBShard{finalHosts[shardIndex], ss.MerkleRoot, ss.SegmentIndex, ss.Nonce}); err != nil {
				return err
			} else if err := sbb.kv.DB.SetChunkShard(c.ID, shardIndex, sid); err != nil {
				return err
			}
		}
		blob.Chunks = append(blob.Chunks, c.ID)
		if err := sbb.kv.DB.AddBlob(blob); err != nil {
			return err
		}
	}
	return nil
}
