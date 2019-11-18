package renterutil

import (
	"strings"
	"sync"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/proto"
)

var errNoHost = errors.New("no record of that host")

type lockedHost struct {
	reconnect func() error
	s         *proto.Session
	mu        sync.Mutex
}

// A HostSet is a collection of renter-host protocol sessions.
type HostSet struct {
	sessions      map[hostdb.HostPublicKey]*lockedHost
	hkr           renter.HostKeyResolver
	currentHeight types.BlockHeight
}

// HasHost returns true if the specified host is in the set.
func (set *HostSet) HasHost(hostKey hostdb.HostPublicKey) bool {
	_, ok := set.sessions[hostKey]
	return ok
}

// Close closes all of the sessions in the set.
func (set *HostSet) Close() error {
	for hostKey, lh := range set.sessions {
		lh.mu.Lock()
		if lh.s != nil {
			lh.s.Close()
			lh.s = nil
		}
		delete(set.sessions, hostKey)
	}
	return nil
}

func (set *HostSet) acquire(host hostdb.HostPublicKey) (*proto.Session, error) {
	ls, ok := set.sessions[host]
	if !ok {
		return nil, errNoHost
	}
	ls.mu.Lock()
	if err := ls.reconnect(); err != nil {
		ls.mu.Unlock()
		return nil, err
	}
	return ls.s, nil
}

func (set *HostSet) release(host hostdb.HostPublicKey) {
	set.sessions[host].mu.Unlock()
}

// AddHost adds a host to the set for later use.
func (set *HostSet) AddHost(c renter.Contract) {
	lh := new(lockedHost)
	// lazy connection function
	lh.reconnect = func() error {
		// even if we have a non-nil Session, the host may have disconnected due
		// to a timeout. To detect this, send a "ping" message (actually a
		// Settings request). If it fails, attempt to reconnect.
		//
		// NOTE: this is somewhat inefficient; it means we incur an extra
		// roundtrip every time we call acquire. The alternative would be for
		// the caller to handle the reconnection logic after calling whatever
		// RPC it wants to call. That way, we only do extra work if the host has
		// actually disconnected. The downside is that we need to wrap every RPC
		// call in reconnection logic (and there's no way to do so generically).
		// So this feels like a reasonable compromise; if the overhead becomes a
		// problem, we can make things uglier and faster later.
		if lh.s != nil {
			if _, err := lh.s.Settings(); err == nil {
				// connection is still open; we're done
				return nil
			}
			// connection timed out, or some other error occurred; close our
			// end (just in case) and fallthrough to the reconnection logic
			lh.s.Close()
			lh.s = nil
		}
		hostIP, err := set.hkr.ResolveHostKey(c.HostKey)
		if err != nil {
			return errors.Wrap(err, "could not resolve host key")
		}
		lh.s, err = proto.NewSession(hostIP, c.HostKey, c.ID, c.RenterKey, set.currentHeight)
		return err
	}
	set.sessions[c.HostKey] = lh
}

// NewHostSet creates an empty HostSet using the provided resolver and current
// height.
func NewHostSet(hkr renter.HostKeyResolver, currentHeight types.BlockHeight) *HostSet {
	return &HostSet{
		hkr:           hkr,
		currentHeight: currentHeight,
		sessions:      make(map[hostdb.HostPublicKey]*lockedHost),
	}
}

// DownloadChunkShards downloads the shards of chunkIndex from hosts in
// parallel. shardLen is the length of the first non-nil shard.
//
// The shards returned by DownloadChunkShards are only valid until the next
// call to Sector on the shard's corresponding proto.Downloader.
func DownloadChunkShards(hosts []*renter.ShardDownloader, chunkIndex int64, minShards int, cancel <-chan struct{}) (shards [][]byte, shardLen int, err error) {
	errNoHost := errors.New("no downloader for this host")
	type result struct {
		shardIndex int
		shard      []byte
		err        error
	}
	// spawn minShards goroutines that receive download requests from
	// reqChan and send responses to resChan.
	reqChan := make(chan int, minShards)
	resChan := make(chan result, minShards)
	var wg sync.WaitGroup
	reqIndex := 0
	for ; reqIndex < minShards; reqIndex++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for shardIndex := range reqChan {
				res := result{shardIndex: shardIndex}
				host := hosts[shardIndex]
				if host == nil {
					res.err = errNoHost
				} else {
					res.shard, res.err = host.DownloadAndDecrypt(chunkIndex)
					res.err = errors.Wrap(res.err, host.HostKey().ShortKey())
				}
				resChan <- res
			}
		}()
		// prepopulate reqChan with first minShards shards
		reqChan <- reqIndex
	}
	// make sure all goroutines exit before returning
	defer func() {
		close(reqChan)
		wg.Wait()
	}()

	// collect the results of each shard download, appending successful
	// downloads to goodRes and failed downloads to badRes. If a download
	// fails, send the next untried shard index. Break as soon as we have
	// minShards successful downloads or if the number of failures makes it
	// impossible to recover the chunk.
	var goodRes, badRes []result
	for len(goodRes) < minShards && len(badRes) <= len(hosts)-minShards {
		select {
		case <-cancel:
			return nil, 0, ErrCanceled

		case res := <-resChan:
			if res.err == nil {
				goodRes = append(goodRes, res)
			} else {
				badRes = append(badRes, res)
				if reqIndex < len(hosts) {
					reqChan <- reqIndex
					reqIndex++
				}
			}
		}
	}
	if len(goodRes) < minShards {
		var errStrings []string
		for _, r := range badRes {
			errStrings = append(errStrings, r.err.Error())
		}
		return nil, 0, errors.New("too many hosts did not supply their shard:\n" + strings.Join(errStrings, "\n"))
	}

	shards = make([][]byte, len(hosts))
	for _, r := range goodRes {
		shards[r.shardIndex] = r.shard
	}

	// determine shardLen
	for _, s := range shards {
		if len(s) > 0 {
			shardLen = len(s)
			break
		}
	}

	// allocate space for missing shards, in case the caller wants to
	// reconstruct them
	for i := range shards {
		if len(shards[i]) == 0 {
			shards[i] = make([]byte, 0, shardLen)
		}
	}

	return shards, shardLen, nil
}
