package renterutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"lukechampine.com/frand"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renterhost"
)

func acquireCtx(ctx context.Context, hosts *HostSet, hostKey hostdb.HostPublicKey, block bool) (*proto.Session, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var (
		sess *proto.Session
		err  error
	)
	done := make(chan struct{})
	go func() {
		sess, err = hosts.tryAcquire(hostKey)
		if err == errHostAcquired && block {
			sess, err = hosts.acquire(hostKey)
		}
		if sess != nil && ctx.Err() != nil {
			hosts.release(hostKey)
		}
		close(done)
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		return sess, err
	}
}

func uploadCtx(ctx context.Context, sess *proto.Session, shard *[renterhost.SectorSize]byte) (root crypto.Hash, err error) {
	if ctx.Err() != nil {
		return crypto.Hash{}, ctx.Err()
	}
	done := make(chan struct{})
	go func() {
		root, err = sess.Append(shard)
		close(done)
	}()
	select {
	case <-ctx.Done():
		sess.Interrupt()
		<-done // wait for goroutine to exit
		err = context.Canceled
	case <-done:
	}
	return
}

func downloadCtx(ctx context.Context, sess *proto.Session, key renter.KeySeed, shard DBShard, offset, length int64) (section []byte, err error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	done := make(chan struct{})
	go func() {
		var buf bytes.Buffer
		err = (&renter.ShardDownloader{
			Downloader: sess,
			Key:        key,
			Slices: []renter.SectorSlice{{
				MerkleRoot:   shard.SectorRoot,
				SegmentIndex: shard.Offset,
				NumSegments:  merkle.SegmentsPerSector - shard.Offset, // inconsequential
				Nonce:        shard.Nonce,
			}},
		}).CopySection(&buf, offset, length)
		section = buf.Bytes()
		close(done)
	}()
	select {
	case <-ctx.Done():
		sess.Interrupt()
		<-done // wait for goroutine to exit
		err = context.Canceled
	case <-done:
	}
	return
}

// A ChunkUploader uploads shards, associating them with a given chunk.
type ChunkUploader interface {
	UploadChunk(ctx context.Context, db MetaDB, c DBChunk, key renter.KeySeed, shards [][]byte) error
}

// SerialChunkUploader uploads chunks to hosts one shard at a time.
type SerialChunkUploader struct {
	Hosts *HostSet
}

// UploadChunk implements ChunkUploader.
func (scu SerialChunkUploader) UploadChunk(ctx context.Context, db MetaDB, c DBChunk, key renter.KeySeed, shards [][]byte) error {
	// choose hosts, preserving any that are already present
	newHosts := make(map[hostdb.HostPublicKey]struct{})
	for h := range scu.Hosts.sessions {
		newHosts[h] = struct{}{}
	}
	need := len(shards)
	skip := make([]bool, len(shards))
	for i, sid := range c.Shards {
		if sid != 0 {
			s, err := db.Shard(sid)
			if err != nil {
				return err
			}
			if scu.Hosts.HasHost(s.HostKey) {
				skip[i] = true
				need--
				delete(newHosts, s.HostKey)
			}
		}
	}
	if need > len(newHosts) {
		return errors.New("fewer hosts than shards")
	}
	chooseHost := func() (h hostdb.HostPublicKey) {
		for h = range newHosts {
			delete(newHosts, h)
			break
		}
		return
	}

	for i, shard := range shards {
		if skip[i] {
			continue
		}
		hostKey := chooseHost()

		var sb renter.SectorBuilder // TODO: reuse
		offset := uint32(sb.Len())
		nonce := renter.RandomNonce()
		sb.Append(shard, key, nonce)
		sector := sb.Finish()
		h, err := scu.Hosts.acquire(hostKey)
		if err != nil {
			return &HostError{hostKey, err}
		}
		root, err := uploadCtx(ctx, h, sector)
		scu.Hosts.release(hostKey)
		if err != nil {
			return &HostError{hostKey, err}
		}

		sid, err := db.AddShard(DBShard{hostKey, root, offset, nonce})
		if err != nil {
			return err
		} else if err := db.SetChunkShard(c.ID, i, sid); err != nil {
			return err
		}
	}
	return nil
}

// ParallelChunkUploader uploads the shards of a chunk in parallel.
type ParallelChunkUploader struct {
	Hosts *HostSet
}

// UploadChunk implements ChunkUploader.
func (pcu ParallelChunkUploader) UploadChunk(ctx context.Context, db MetaDB, c DBChunk, key renter.KeySeed, shards [][]byte) error {
	if len(shards) > len(pcu.Hosts.sessions) {
		return errors.New("more shards than hosts")
	}
	// choose hosts, preserving any that are already present
	newHosts := make(map[hostdb.HostPublicKey]struct{})
	for h := range pcu.Hosts.sessions {
		newHosts[h] = struct{}{}
	}
	rem := len(shards)
	skip := make([]bool, len(shards))
	for i, sid := range c.Shards {
		if sid != 0 {
			s, err := db.Shard(sid)
			if err != nil {
				return err
			}
			if pcu.Hosts.HasHost(s.HostKey) {
				skip[i] = true
				rem--
				delete(newHosts, s.HostKey)
			}
		}
	}
	if rem > len(newHosts) {
		rem = len(newHosts)
	}

	chooseHost := func() (h hostdb.HostPublicKey) {
		for h = range newHosts {
			delete(newHosts, h)
			break
		}
		return
	}

	// spawn workers
	type req struct {
		shardIndex int
		hostKey    hostdb.HostPublicKey
		shard      *[renterhost.SectorSize]byte
		nonce      [24]byte
		block      bool // wait to acquire
	}
	type resp struct {
		req     req
		sliceID uint64
		err     error
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
				sess, err := acquireCtx(ctx, pcu.Hosts, req.hostKey, req.block)
				if err != nil {
					respChan <- resp{req, 0, err}
					continue
				}

				root, err := uploadCtx(ctx, sess, req.shard)
				pcu.Hosts.release(req.hostKey)
				if err != nil {
					respChan <- resp{req, 0, err}
					continue
				}

				// TODO: need to use sb.Len as offset if reusing sb, i.e. when buffering
				ssid, err := db.AddShard(DBShard{req.hostKey, root, 0, req.nonce})
				respChan <- resp{req, ssid, err}
			}
		}()
	}

	// construct sectors
	sectors := make([]*[renterhost.SectorSize]byte, len(c.Shards))
	nonces := make([][24]byte, len(sectors))
	for i, shard := range shards {
		if skip[i] {
			continue
		}
		nonces[i] = renter.RandomNonce()
		var sb renter.SectorBuilder
		sb.Append(shard, key, nonces[i])
		sectors[i] = sb.Finish()
	}

	// start by requesting uploads to rem hosts, non-blocking.
	var inflight int
	for shardIndex := range c.Shards {
		if skip[shardIndex] || len(newHosts) == 0 {
			continue
		}
		reqChan <- req{
			shardIndex: shardIndex,
			hostKey:    chooseHost(),
			shard:      sectors[shardIndex],
			nonce:      nonces[shardIndex],
			block:      false,
		}
		inflight++
	}

	// for those that return errors, add the next host to the queue, non-blocking.
	// for those that block, add the same host to the queue, blocking.
	var reqQueue []req
	var errs HostErrorSet
	for inflight > 0 {
		resp := <-respChan
		inflight--
		if resp.err == nil {
			if err := db.SetChunkShard(c.ID, resp.req.shardIndex, resp.sliceID); err != nil {
				// NOTE: in theory, we could attempt to continue storing the
				// remaining successful shards, but in practice, if
				// SetChunkShards fails, it indicates a serious problem with the
				// db, and subsequent calls to SetChunkShards are not likely to
				// succeed.
				for inflight > 0 {
					<-respChan
					inflight--
				}
				return err
			}
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
	return nil
}

// MinimumChunkUploader uploads shards one at a time, stopping as soon as
// MinShards shards have been uploaded.
type MinimumChunkUploader struct {
	Hosts *HostSet
}

// UploadChunk implements ChunkUploader.
func (mcu MinimumChunkUploader) UploadChunk(ctx context.Context, db MetaDB, c DBChunk, key renter.KeySeed, shards [][]byte) error {
	// choose hosts, preserving any that are already present
	newHosts := make(map[hostdb.HostPublicKey]struct{})
	for h := range mcu.Hosts.sessions {
		newHosts[h] = struct{}{}
	}
	need := int(c.MinShards)
	skip := make([]bool, len(shards))
	for i, sid := range c.Shards {
		if sid != 0 {
			s, err := db.Shard(sid)
			if err != nil {
				return err
			}
			if mcu.Hosts.HasHost(s.HostKey) {
				skip[i] = true
				need--
				delete(newHosts, s.HostKey)
			}
		}
	}
	if need > len(newHosts) {
		return errors.New("fewer hosts than shards")
	} else if need <= 0 {
		return nil // already have minimum
	}
	chooseHost := func() (h hostdb.HostPublicKey) {
		for h = range newHosts {
			delete(newHosts, h)
			break
		}
		return
	}
	for i, shard := range shards {
		if skip[i] {
			continue
		}
		hostKey := chooseHost()

		nonce := renter.RandomNonce()
		var sb renter.SectorBuilder // TODO: reuse
		offset := uint32(sb.Len())
		sb.Append(shard, key, nonce)
		sector := sb.Finish()
		h, err := mcu.Hosts.acquire(hostKey)
		if err != nil {
			return &HostError{hostKey, err}
		}
		root, err := uploadCtx(ctx, h, sector)
		mcu.Hosts.release(hostKey)
		if err != nil {
			return &HostError{hostKey, err}
		}

		if sid, err := db.AddShard(DBShard{hostKey, root, offset, nonce}); err != nil {
			return err
		} else if err := db.SetChunkShard(c.ID, i, sid); err != nil {
			return err
		}

		if need--; need == 0 {
			break
		}
	}
	return nil
}

// OverdriveChunkUploader uploads the shards of a chunk in parallel, using up to
// N overdrive hosts.
type OverdriveChunkUploader struct {
	Hosts     *HostSet
	Overdrive int
}

// UploadChunk implements ChunkUploader.
func (ocu OverdriveChunkUploader) UploadChunk(ctx context.Context, db MetaDB, c DBChunk, key renter.KeySeed, shards [][]byte) error {
	if ocu.Overdrive < 0 {
		panic("overdrive cannot be negative")
	}

	// choose hosts, preserving any that are already present
	newHosts := make(map[hostdb.HostPublicKey]struct{})
	for h := range ocu.Hosts.sessions {
		newHosts[h] = struct{}{}
	}
	rem := len(shards)
	skip := make([]bool, len(shards))
	for i, sid := range c.Shards {
		if sid != 0 {
			s, err := db.Shard(sid)
			if err != nil {
				return err
			}
			if ocu.Hosts.HasHost(s.HostKey) {
				skip[i] = true
				rem--
				delete(newHosts, s.HostKey)
			}
		}
	}
	if rem > len(newHosts) {
		rem = len(newHosts)
	}

	// spawn workers
	numWorkers := rem + ocu.Overdrive
	if numWorkers > len(newHosts) {
		numWorkers = len(newHosts)
	}
	type req struct {
		shardIndex int
		hostKey    hostdb.HostPublicKey
		shard      *[renterhost.SectorSize]byte
		nonce      [24]byte
		block      bool // wait to acquire
	}
	type resp struct {
		req  req
		root crypto.Hash
		err  error
	}
	reqChan := make(chan req, numWorkers)
	respChan := make(chan resp, numWorkers)
	var wg sync.WaitGroup
	wg.Add(numWorkers)
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		// cancel any outstanding uploads and wait for them to exit
		close(reqChan)
		cancel()
		wg.Wait()
	}()
	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()
			for req := range reqChan {
				sess, err := acquireCtx(ctx, ocu.Hosts, req.hostKey, req.block)
				if err != nil {
					respChan <- resp{req, crypto.Hash{}, err}
					continue
				}
				root, err := uploadCtx(ctx, sess, req.shard)
				ocu.Hosts.release(req.hostKey)
				if err != nil {
					respChan <- resp{req, crypto.Hash{}, err}
					continue
				}
				respChan <- resp{req, root, err}
			}
		}()
	}

	// construct sectors
	sectors := make([]*[renterhost.SectorSize]byte, len(c.Shards))
	nonces := make([][24]byte, len(sectors))
	for i, shard := range shards {
		if skip[i] {
			continue
		}
		nonces[i] = renter.RandomNonce()
		var sb renter.SectorBuilder
		sb.Append(shard, key, nonces[i])
		sectors[i] = sb.Finish()
	}

	// start by requesting one upload per worker, all non-blocking.
	var reqQueue []req
	i := 0
	for h := range newHosts {
	again:
		shardIndex := i % len(c.Shards)
		i++
		if skip[shardIndex] {
			goto again
		}
		reqQueue = append(reqQueue, req{
			shardIndex: shardIndex,
			hostKey:    h,
			shard:      sectors[shardIndex],
			nonce:      nonces[shardIndex],
			block:      false,
		})
	}
	for _, req := range reqQueue[:numWorkers] {
		reqChan <- req
	}
	reqQueue = reqQueue[numWorkers:]
	inflight := numWorkers

	// for those that return errors, add the next host to the queue, non-blocking.
	// for those that block, add the same host to the queue, blocking.
	success := make([]bool, len(c.Shards))
	var errs HostErrorSet
	for rem > 0 && inflight > 0 {
		resp := <-respChan
		inflight--
		if resp.err == nil {
			if success[resp.req.shardIndex] {
				continue // an earlier worker already succeeded
			}
			// NOTE: in theory, we could attempt to continue storing the
			// remaining successful shards, but in practice, if
			// SetChunkShard fails, it indicates a serious problem with the
			// db and subsequent calls are not likely to succeed.
			if ssid, err := db.AddShard(DBShard{resp.req.hostKey, resp.root, 0, resp.req.nonce}); err != nil {
				return err
			} else if err := db.SetChunkShard(c.ID, resp.req.shardIndex, ssid); err != nil {
				return err
			}
			rem--
			success[resp.req.shardIndex] = true
		} else {
			if resp.err == errHostAcquired {
				// host could not be acquired without blocking; add it to the back
				// of the queue, but next time, block
				resp.req.block = true
				reqQueue = append(reqQueue, resp.req)
			} else {
				// uploading to this host failed; don't try it again
				errs = append(errs, &HostError{resp.req.hostKey, resp.err})
			}
			// try the next host in the queue
			if len(reqQueue) > 0 {
				reqChan <- reqQueue[0]
				reqQueue = reqQueue[1:]
				inflight++
			}
		}
	}
	if rem > 0 {
		return fmt.Errorf("could not upload to enough hosts: %w", errs)
	}
	return nil
}

// A ChunkDownloader downloads the shards of a chunk.
type ChunkDownloader interface {
	DownloadChunk(ctx context.Context, db MetaDB, c DBChunk, key renter.KeySeed, off, n int64) ([][]byte, error)
}

// SerialChunkDownloader downloads the shards of a chunk one at a time.
type SerialChunkDownloader struct {
	Hosts *HostSet
}

// DownloadChunk implements ChunkDownloader.
func (scd SerialChunkDownloader) DownloadChunk(ctx context.Context, db MetaDB, c DBChunk, key renter.KeySeed, off, n int64) ([][]byte, error) {
	minChunkSize := merkle.SegmentSize * int64(c.MinShards)
	shards := make([][]byte, len(c.Shards))
	for i := range shards {
		shards[i] = make([]byte, 0, renterhost.SectorSize)
	}
	var errs HostErrorSet
	need := c.MinShards
	for i, ssid := range c.Shards {
		shard, err := db.Shard(ssid)
		if err != nil {
			return nil, err
		}

		start := (off / minChunkSize) * merkle.SegmentSize
		end := ((off + n) / minChunkSize) * merkle.SegmentSize
		if (off+n)%minChunkSize != 0 {
			end += merkle.SegmentSize
		}
		offset, length := start, end-start

		sess, err := scd.Hosts.acquire(shard.HostKey)
		if err != nil {
			errs = append(errs, &HostError{shard.HostKey, err})
			continue
		}
		section, err := downloadCtx(ctx, sess, key, shard, offset, length)
		scd.Hosts.release(shard.HostKey)
		if err != nil {
			errs = append(errs, &HostError{shard.HostKey, err})
			continue
		}
		shards[i] = section
		if need--; need == 0 {
			break
		}
	}
	if need != 0 {
		return nil, errs
	}
	return shards, nil
}

// ParallelChunkDownloader downloads the shards of a chunk in parallel.
type ParallelChunkDownloader struct {
	Hosts *HostSet
}

// DownloadChunk implements ChunkDownloader.
func (pcd ParallelChunkDownloader) DownloadChunk(ctx context.Context, db MetaDB, c DBChunk, key renter.KeySeed, off, n int64) ([][]byte, error) {
	minChunkSize := merkle.SegmentSize * int64(c.MinShards)
	start := (off / minChunkSize) * merkle.SegmentSize
	end := ((off + n) / minChunkSize) * merkle.SegmentSize
	if (off+n)%minChunkSize != 0 {
		end += merkle.SegmentSize
	}
	offset, length := start, end-start

	// download shards in parallel, stopping when we have any c.MinShards of
	// them
	shards := make([][]byte, len(c.Shards))
	for i := range shards {
		shards[i] = make([]byte, 0, length)
	}
	type req struct {
		shardIndex int
		block      bool // wait to acquire
	}
	type resp struct {
		shardIndex int
		err        *HostError
	}
	reqChan := make(chan req, c.MinShards)
	respChan := make(chan resp, c.MinShards)
	reqQueue := make([]req, len(c.Shards))
	// initialize queue in random order
	for i, shardIndex := range frand.Perm(len(reqQueue)) {
		reqQueue[i] = req{shardIndex, false}
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	for len(reqQueue) > len(c.Shards)-int(c.MinShards) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range reqChan {
				shard, err := db.Shard(c.Shards[req.shardIndex])
				if err != nil {
					respChan <- resp{req.shardIndex, &HostError{shard.HostKey, err}}
					continue
				}

				sess, err := acquireCtx(ctx, pcd.Hosts, shard.HostKey, req.block)
				if err != nil {
					respChan <- resp{req.shardIndex, &HostError{shard.HostKey, err}}
					continue
				}
				section, err := downloadCtx(ctx, sess, key, shard, offset, length)
				pcd.Hosts.release(shard.HostKey)
				if err != nil {
					respChan <- resp{req.shardIndex, &HostError{shard.HostKey, err}}
					continue
				}
				shards[req.shardIndex] = section
				respChan <- resp{req.shardIndex, nil}
			}
		}()
		reqChan <- reqQueue[0]
		reqQueue = reqQueue[1:]
	}

	var goodShards int
	var errs HostErrorSet
	for goodShards < int(c.MinShards) && goodShards+len(errs) < len(c.Shards) {
		resp := <-respChan
		if resp.err == nil {
			goodShards++
		} else {
			if resp.err.Err == errHostAcquired {
				// host could not be acquired without blocking; add it to the back
				// of the queue, but next time, block
				reqQueue = append(reqQueue, req{
					shardIndex: resp.shardIndex,
					block:      true,
				})
			} else {
				// downloading from this host failed; don't try it again
				errs = append(errs, resp.err)
			}
			// try the next host in the queue
			if len(reqQueue) > 0 {
				reqChan <- reqQueue[0]
				reqQueue = reqQueue[1:]
			}
		}
	}
	close(reqChan)
	if goodShards < int(c.MinShards) {
		return nil, fmt.Errorf("too many hosts did not supply their shard (needed %v, got %v): %w", c.MinShards, goodShards, errs)
	}
	return shards, nil
}

// OverdriveChunkDownloader downloads the shards of a chunk in parallel.
type OverdriveChunkDownloader struct {
	Hosts     *HostSet
	Overdrive int
}

// DownloadChunk implements ChunkDownloader.
func (ocd OverdriveChunkDownloader) DownloadChunk(ctx context.Context, db MetaDB, c DBChunk, key renter.KeySeed, off, n int64) ([][]byte, error) {
	if ocd.Overdrive < 0 {
		panic("overdrive cannot be negative")
	}
	numWorkers := int(c.MinShards) + ocd.Overdrive
	if numWorkers > len(c.Shards) {
		numWorkers = len(c.Shards)
	}

	minChunkSize := merkle.SegmentSize * int64(c.MinShards)
	start := (off / minChunkSize) * merkle.SegmentSize
	end := ((off + n) / minChunkSize) * merkle.SegmentSize
	if (off+n)%minChunkSize != 0 {
		end += merkle.SegmentSize
	}
	offset, length := start, end-start

	// download shards in parallel, stopping when we have any c.MinShards of
	// them
	type req struct {
		shardIndex int
		block      bool // wait to acquire
	}
	type resp struct {
		req   req
		shard []byte
		err   *HostError
	}
	reqChan := make(chan req, numWorkers)
	respChan := make(chan resp, numWorkers)
	var wg sync.WaitGroup
	wg.Add(numWorkers)
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		close(reqChan)
		cancel()
		wg.Wait()
	}()
	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()
			for req := range reqChan {
				shard, err := db.Shard(c.Shards[req.shardIndex])
				if err != nil {
					respChan <- resp{req, nil, &HostError{shard.HostKey, err}}
					continue
				}
				sess, err := acquireCtx(ctx, ocd.Hosts, shard.HostKey, req.block)
				if err != nil {
					respChan <- resp{req, nil, &HostError{shard.HostKey, err}}
					continue
				}

				section, err := downloadCtx(ctx, sess, key, shard, offset, length)
				ocd.Hosts.release(shard.HostKey)
				if err != nil {
					respChan <- resp{req, nil, &HostError{shard.HostKey, err}}
					continue
				}
				respChan <- resp{req, section, nil}
			}
		}()
	}

	// initialize queue in random order
	reqQueue := make([]req, len(c.Shards))
	for i, shardIndex := range frand.Perm(len(reqQueue)) {
		reqQueue[i] = req{shardIndex, false}
	}
	// send initial requests
	for _, req := range reqQueue[:numWorkers] {
		reqChan <- req
	}
	reqQueue = reqQueue[numWorkers:]

	// await responses and replace failed requests as necessary
	shards := make([][]byte, len(c.Shards))
	for i := range shards {
		shards[i] = make([]byte, 0, length)
	}
	var goodShards int
	var errs HostErrorSet
	for goodShards < int(c.MinShards) && goodShards+len(errs) < len(c.Shards) {
		resp := <-respChan
		if resp.err == nil {
			goodShards++
			shards[resp.req.shardIndex] = resp.shard
		} else {
			if resp.err.Err == errHostAcquired {
				// host could not be acquired without blocking; add it to the back
				// of the queue, but next time, block
				resp.req.block = true
				reqQueue = append(reqQueue, resp.req)
			} else {
				// downloading from this host failed; don't try it again
				errs = append(errs, resp.err)
			}
			// try the next host in the queue
			if len(reqQueue) > 0 {
				reqChan <- reqQueue[0]
				reqQueue = reqQueue[1:]
			}
		}
	}
	if goodShards < int(c.MinShards) {
		return nil, fmt.Errorf("too many hosts did not supply their shard (needed %v, got %v): %w", c.MinShards, goodShards, errs)
	}
	return shards, nil
}

// A ChunkUpdater updates or replaces an existing chunk, returning the ID of the
// new chunk.
type ChunkUpdater interface {
	UpdateChunk(ctx context.Context, db MetaDB, b DBBlob, c DBChunk) (uint64, error)
}

// GenericChunkUpdater updates chunks by downloading them with D and reuploading
// them with U, using erasure-coding parameters M and N.
type GenericChunkUpdater struct {
	D    ChunkDownloader
	U    ChunkUploader
	M, N int

	// If true, the chunk's encoding parameters are used, and the chunk is
	// updated directly instead of a new chunk being added to the DB.
	InPlace bool

	// If non-nil, skip any chunk for which this function returns false.
	ShouldUpdate func(MetaDB, DBChunk) (bool, error)
}

// UpdateChunk implements ChunkUpdater.
func (gcu GenericChunkUpdater) UpdateChunk(ctx context.Context, db MetaDB, b DBBlob, c DBChunk) (uint64, error) {
	if gcu.ShouldUpdate != nil {
		shouldUpdate, err := gcu.ShouldUpdate(db, c)
		if err != nil {
			return 0, err
		} else if !shouldUpdate {
			return c.ID, nil
		}
	}

	// download
	shards, err := gcu.D.DownloadChunk(ctx, db, c, b.Seed, 0, int64(c.Len))
	if err != nil {
		return 0, err
	}

	// reshard
	m, n := gcu.M, gcu.N
	if gcu.InPlace {
		m, n = int(c.MinShards), len(c.Shards)
	}
	if m == int(c.MinShards) && n == len(c.Shards) {
		if err := renter.NewRSCode(m, n).Reconstruct(shards); err != nil {
			return 0, err
		}
	} else {
		var buf bytes.Buffer
		if err := renter.NewRSCode(int(c.MinShards), len(c.Shards)).Recover(&buf, shards, 0, int(c.Len)); err != nil {
			return 0, err
		}
		shards = make([][]byte, n)
		for i := range shards {
			shards[i] = make([]byte, renterhost.SectorSize)
		}
		renter.NewRSCode(m, n).Encode(buf.Bytes(), shards)
	}

	// upload
	if !gcu.InPlace {
		c, err = db.AddChunk(m, n, c.Len)
		if err != nil {
			return 0, err
		}
	}
	if err := gcu.U.UploadChunk(ctx, db, c, b.Seed, shards); err != nil {
		return 0, err
	}
	return c.ID, nil
}

// NewMigrationWhitelist returns a filter for use with GenericChunkUpdater. It
// returns true for chunks that store all of their shards on whitelisted host.
func NewMigrationWhitelist(whitelist []hostdb.HostPublicKey) func(MetaDB, DBChunk) (bool, error) {
	return func(db MetaDB, c DBChunk) (bool, error) {
		for _, id := range c.Shards {
			s, err := db.Shard(id)
			if err != nil {
				return false, err
			}
			whitelisted := false
			for _, h := range whitelist {
				whitelisted = whitelisted || h == s.HostKey
			}
			if !whitelisted {
				return true, nil
			}
		}
		return false, nil
	}
}

// NewMigrationBlacklist returns a filter for use with GenericChunkUpdater. It
// returns true for chunks that store any of their shards on a blacklisted host.
func NewMigrationBlacklist(blacklist []hostdb.HostPublicKey) func(MetaDB, DBChunk) (bool, error) {
	return func(db MetaDB, c DBChunk) (bool, error) {
		for _, id := range c.Shards {
			s, err := db.Shard(id)
			if err != nil {
				return false, err
			}
			for _, h := range blacklist {
				if h == s.HostKey {
					return true, nil
				}
			}
		}
		return false, nil
	}
}

// A BlobUploader uploads a DBBlob.
type BlobUploader interface {
	UploadBlob(ctx context.Context, db MetaDB, b DBBlob, r io.Reader) error
}

// SerialBlobUploader uploads the chunks of a blob one at a time.
type SerialBlobUploader struct {
	U    ChunkUploader
	M, N int
}

// UploadBlob implements BlobUploader.
func (sbu SerialBlobUploader) UploadBlob(ctx context.Context, db MetaDB, b DBBlob, r io.Reader) error {
	rsc := renter.NewRSCode(sbu.M, sbu.N)
	shards := make([][]byte, sbu.N)
	for i := range shards {
		shards[i] = make([]byte, renterhost.SectorSize)
	}
	buf := make([]byte, renterhost.SectorSize*sbu.M)
	for {
		chunkLen, err := io.ReadFull(r, buf)
		if err == io.EOF {
			break
		} else if err != nil && err != io.ErrUnexpectedEOF {
			return err
		}
		rsc.Encode(buf[:chunkLen], shards)
		c, err := db.AddChunk(sbu.M, sbu.N, uint64(chunkLen))
		if err != nil {
			return err
		}
		b.Chunks = append(b.Chunks, c.ID)
		if err := db.AddBlob(b); err != nil {
			return err
		}
		if err := sbu.U.UploadChunk(ctx, db, c, b.Seed, shards); err != nil {
			return err
		}
	}
	return nil
}

// ParallelBlobUploader uploads the chunks of a blob in parallel.
type ParallelBlobUploader struct {
	U    ChunkUploader
	M, N int
	P    int // degree of parallelism
}

// UploadBlob implements BlobUploader.
func (pbu ParallelBlobUploader) UploadBlob(ctx context.Context, db MetaDB, b DBBlob, r io.Reader) error {
	// spawn p workers
	type req struct {
		c      DBChunk
		shards [][]byte
	}
	reqChan := make(chan req)
	respChan := make(chan error)
	var wg sync.WaitGroup
	defer wg.Wait()
	for i := 0; i < pbu.P; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range reqChan {
				respChan <- pbu.U.UploadChunk(ctx, db, req.c, b.Seed, req.shards)
			}
		}()
	}

	var inflight int
	consumeResp := func() error {
		err := <-respChan
		inflight--
		return err
	}
	defer func() {
		close(reqChan)
		for inflight > 0 {
			_ = consumeResp()
		}
	}()

	// read+encode chunks, add to db, send requests to workers
	rsc := renter.NewRSCode(pbu.M, pbu.N)
	buf := make([]byte, renterhost.SectorSize*pbu.M)
	for {
		chunkLen, err := io.ReadFull(r, buf)
		if err == io.EOF {
			break
		} else if err != nil && err != io.ErrUnexpectedEOF {
			return err
		}

		shards := make([][]byte, pbu.N)
		for i := range shards {
			shards[i] = make([]byte, renterhost.SectorSize)
		}
		rsc.Encode(buf[:chunkLen], shards)
		c, err := db.AddChunk(pbu.M, pbu.N, uint64(chunkLen))
		if err != nil {
			return err
		}
		b.Chunks = append(b.Chunks, c.ID)
		if err := db.AddBlob(b); err != nil {
			return err
		}
		reqChan <- req{c, shards}
		inflight++
		if inflight == pbu.P {
			if err := consumeResp(); err != nil {
				return err
			}
		}
	}
	// all requests have been sent; wait for inflight uploads to complete
	for inflight > 0 {
		if err := consumeResp(); err != nil {
			return err
		}
	}
	return nil
}

// A BlobDownloader downloads blob data, writing it to w.
type BlobDownloader interface {
	DownloadBlob(ctx context.Context, db MetaDB, b DBBlob, w io.Writer, off, n int64) error
}

// SerialBlobDownloader downloads the chunks of a blob one at a time.
type SerialBlobDownloader struct {
	D ChunkDownloader
}

// DownloadBlob implements BlobDownloader.
func (sbd SerialBlobDownloader) DownloadBlob(ctx context.Context, db MetaDB, b DBBlob, w io.Writer, off, n int64) error {
	for _, cid := range b.Chunks {
		c, err := db.Chunk(cid)
		if err != nil {
			return err
		}
		if off >= int64(c.Len) {
			off -= int64(c.Len)
			continue
		}

		reqLen := n
		if reqLen < 0 || reqLen > int64(c.Len) {
			reqLen = int64(c.Len)
		}
		shards, err := sbd.D.DownloadChunk(ctx, db, c, b.Seed, off, reqLen)
		if err != nil {
			return err
		}

		rsc := renter.NewRSCode(int(c.MinShards), len(c.Shards))
		skip := int(off % (merkle.SegmentSize * int64(c.MinShards)))
		if err := rsc.Recover(w, shards, skip, int(reqLen)); err != nil {
			return err
		}
		off = 0
		n -= reqLen
		if n == 0 {
			break
		}
	}
	return nil
}

// ParallelBlobDownloader downloads the chunks of a blob in parallel.
type ParallelBlobDownloader struct {
	D ChunkDownloader
	P int // degree of parallelism
}

// DownloadBlob implements BlobDownloader.
func (pbd ParallelBlobDownloader) DownloadBlob(ctx context.Context, db MetaDB, b DBBlob, w io.Writer, off, n int64) error {
	// spawn workers
	type req struct {
		c      DBChunk
		off, n int64
		index  int
	}
	type resp struct {
		index int
		chunk []byte
		err   error
	}
	reqChan := make(chan req)
	respChan := make(chan resp)
	var wg sync.WaitGroup
	defer wg.Wait()
	for i := 0; i < pbd.P; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range reqChan {
				shards, err := pbd.D.DownloadChunk(ctx, db, req.c, b.Seed, req.off, req.n)
				if err != nil {
					respChan <- resp{req.index, nil, err}
					continue
				}
				rsc := renter.NewRSCode(int(req.c.MinShards), len(req.c.Shards))
				skip := int(req.off % (merkle.SegmentSize * int64(req.c.MinShards)))
				var buf bytes.Buffer
				if err := rsc.Recover(&buf, shards, skip, int(req.n)); err != nil {
					respChan <- resp{req.index, nil, err}
					continue
				}
				respChan <- resp{req.index, buf.Bytes(), err}
			}
		}()
	}

	// when a response arrives, write the chunk into a circular buffer, then
	// flush as many chunks as possible
	chunks := make([][]byte, pbd.P)
	pos := 0
	inflight := 0
	consumeResp := func() error {
		resp := <-respChan
		inflight--
		if resp.err != nil {
			return resp.err
		}
		// write + flush
		if chunks[resp.index%pbd.P] != nil {
			panic("refusing to overwrite chunk")
		}
		chunks[resp.index%pbd.P] = resp.chunk
		for i := pos % pbd.P; chunks[i] != nil; i = pos % pbd.P {
			if _, err := w.Write(chunks[i]); err != nil {
				return err
			}
			chunks[i] = nil
			pos++
		}
		return nil
	}

	// if we return early (due to an error), ensure that we consume all
	// outstanding requests
	defer func() {
		close(reqChan)
		for inflight > 0 {
			_ = consumeResp()
		}
	}()

	// request each chunk
	for chunkIndex, cid := range b.Chunks {
		c, err := db.Chunk(cid)
		if err != nil {
			return err
		}
		if off >= int64(c.Len) {
			off -= int64(c.Len)
			continue
		}
		reqLen := n
		if reqLen < 0 || reqLen > int64(c.Len) {
			reqLen = int64(c.Len)
		}
		reqChan <- req{c, off, reqLen, chunkIndex}
		inflight++

		// clear offset (as it only applies to the first chunk) and break early
		// if all necessary chunks have been requested
		off = 0
		n -= reqLen
		if n == 0 {
			break
		}

		// if all workers are busy, wait for one to finish before proceeding
		if inflight == pbd.P {
			if err := consumeResp(); err != nil {
				return err
			}
		}
	}

	// all requests have been sent; wait for inflight downloads to complete
	for inflight > 0 {
		if err := consumeResp(); err != nil {
			return err
		}
	}

	return nil
}

// A BlobUpdater updates the contents of a blob.
type BlobUpdater interface {
	UpdateBlob(ctx context.Context, db MetaDB, b DBBlob) error
}

// SerialBlobUpdater uploads the chunks of a blob one at a time.
type SerialBlobUpdater struct {
	U ChunkUpdater
}

// UpdateBlob implements BlobUpdater.
func (sbu SerialBlobUpdater) UpdateBlob(ctx context.Context, db MetaDB, b DBBlob) error {
	for i, cid := range b.Chunks {
		c, err := db.Chunk(cid)
		if err != nil {
			return err
		}
		id, err := sbu.U.UpdateChunk(ctx, db, b, c)
		if err != nil {
			return err
		}
		if cid != id {
			b.Chunks[i] = id
			if err := db.AddBlob(b); err != nil {
				return err
			}
		}
	}
	return nil
}

// A SectorDeleter deletes sectors from hosts.
type SectorDeleter interface {
	DeleteSectors(ctx context.Context, db MetaDB, sectors map[hostdb.HostPublicKey][]crypto.Hash) error
}

// SerialSectorDeleter deletes sectors from hosts, one host at a time.
type SerialSectorDeleter struct {
	Hosts *HostSet
}

// DeleteSectors implements SectorDeleter.
func (ssd SerialSectorDeleter) DeleteSectors(ctx context.Context, db MetaDB, sectors map[hostdb.HostPublicKey][]crypto.Hash) error {
	for hostKey, roots := range sectors {
		h, err := ssd.Hosts.acquire(hostKey)
		if err != nil {
			return err
		}
		// TODO: no-op if roots already deleted
		// TODO: respect ctx
		err = h.DeleteSectors(roots)
		ssd.Hosts.release(hostKey)
		if err != nil {
			return err
		}
		// TODO: mark sectors as deleted in db
	}
	return nil
}

// ParallelSectorDeleter deletes sectors from hosts in parallel.
type ParallelSectorDeleter struct {
	Hosts *HostSet
}

// DeleteSectors implements SectorDeleter.
func (psd ParallelSectorDeleter) DeleteSectors(ctx context.Context, db MetaDB, sectors map[hostdb.HostPublicKey][]crypto.Hash) error {
	errCh := make(chan *HostError)
	for hostKey, roots := range sectors {
		go func(hostKey hostdb.HostPublicKey, roots []crypto.Hash) {
			errCh <- func() *HostError {
				h, err := psd.Hosts.acquire(hostKey)
				if err != nil {
					return &HostError{hostKey, err}
				}
				// TODO: no-op if roots already deleted
				// TODO: respect ctx
				err = h.DeleteSectors(roots)
				psd.Hosts.release(hostKey)
				if err != nil {
					return &HostError{hostKey, err}
				}
				// TODO: mark sectors as deleted in db
				return nil
			}()
		}(hostKey, roots)
	}
	var errs HostErrorSet
	for range sectors {
		if err := <-errCh; err != nil {
			errs = append(errs, err)
		}
	}
	if errs != nil {
		return fmt.Errorf("could not delete from all hosts: %w", errs)
	}
	return nil
}
