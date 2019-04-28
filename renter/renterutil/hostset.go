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
	s   *proto.Session
	err error
	mu  *sync.Mutex
}

// A HostSet is a collection of renter-host protocol sessions.
type HostSet struct {
	sessions map[hostdb.HostPublicKey]lockedHost
}

// Close closes all of the Downloaders in the set.
func (set *HostSet) Close() error {
	for _, ls := range set.sessions {
		ls.mu.Lock()
		if ls.s != nil {
			ls.s.Close()
		}
	}
	return nil
}

func (set *HostSet) acquire(host hostdb.HostPublicKey) (*proto.Session, error) {
	ls, ok := set.sessions[host]
	if !ok {
		return nil, errNoHost
	}
	ls.mu.Lock()
	if err := ls.err; err != nil {
		ls.mu.Unlock()
		return nil, err
	}
	return ls.s, nil
}

func (set *HostSet) release(host hostdb.HostPublicKey) {
	set.sessions[host].mu.Unlock()
}

// NewHostSet creates a HostSet composed of one protocol session per contract.
// If a session cannot be established, that contract is skipped; these errors
// are exposed via the acquire method.
func NewHostSet(contracts renter.ContractSet, hkr renter.HostKeyResolver, currentHeight types.BlockHeight) *HostSet {
	hs := &HostSet{
		sessions: make(map[hostdb.HostPublicKey]lockedHost),
	}
	for hostKey, contract := range contracts {
		hostIP, err := hkr.ResolveHostKey(contract.HostKey())
		if err != nil {
			err = errors.Wrapf(err, "%v: could not resolve host key", hostKey.ShortKey())
			hs.sessions[hostKey] = lockedHost{err: err, mu: new(sync.Mutex)}
			continue
		}
		s, err := proto.NewSession(hostIP, contract, currentHeight)
		if err != nil {
			err = errors.Wrapf(err, "%v", hostKey.ShortKey())
			hs.sessions[hostKey] = lockedHost{err: err, mu: new(sync.Mutex)}
			continue
		}
		hs.sessions[hostKey] = lockedHost{s: s, mu: new(sync.Mutex)}
	}
	return hs
}

// DownloadChunkShards downloads the shards of chunkIndex from hosts in
// parallel. shardLen is the length of the first non-nil shard.
//
// The shards returned by DownloadChunkShards are only valid until the next
// call to Sector on the shard's corresponding proto.Downloader.
func DownloadChunkShards(hosts []*renter.ShardDownloader, chunkIndex int64, minShards int, cancel <-chan struct{}) (shards [][]byte, shardLen int, stats []DownloadStatsUpdate, err error) {
	errNoHost := errors.New("no downloader for this host")
	type result struct {
		shardIndex int
		shard      []byte
		stats      DownloadStatsUpdate
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
					res.stats = DownloadStatsUpdate{
						Host:  host.HostKey(),
						Stats: host.Downloader.LastDownloadStats(),
					}
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
			return nil, 0, nil, ErrCanceled

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
			if r.err != errNoHost {
				errStrings = append(errStrings, r.err.Error())
			}
		}
		return nil, 0, nil, errors.New("too many hosts did not supply their shard:\n" + strings.Join(errStrings, "\n"))
	}

	shards = make([][]byte, len(hosts))
	stats = make([]DownloadStatsUpdate, 0, len(goodRes))
	for _, r := range goodRes {
		shards[r.shardIndex] = r.shard
		stats = append(stats, r.stats)
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

	return shards, shardLen, stats, nil
}
