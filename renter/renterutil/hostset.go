package renterutil

import (
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/proto"
)

var errNoHost = errors.New("no record of that host")
var errHostAcquired = errors.New("host is currently acquired")

// A HostError associates an error with a given host.
type HostError struct {
	HostKey hostdb.HostPublicKey
	Err     error
}

// Error implements error.
func (he HostError) Error() string {
	return he.HostKey.ShortKey() + ": " + he.Err.Error()
}

// Unwrap returns the underlying error.
func (he HostError) Unwrap() error {
	return he.Err
}

// A HostErrorSet is a collection of errors from various hosts.
type HostErrorSet []*HostError

// Error implements error.
func (hes HostErrorSet) Error() string {
	strs := make([]string, len(hes))
	for i := range strs {
		strs[i] = hes[i].Error()
	}
	// include a leading newline so that the first error isn't printed on the
	// same line as the error context
	return "\n" + strings.Join(strs, "\n")
}

type tryLock struct {
	c    chan struct{}
	once sync.Once
}

func (mu *tryLock) init() {
	mu.c = make(chan struct{}, 1)
	mu.c <- struct{}{}
}

func (mu *tryLock) Lock() {
	mu.once.Do(mu.init)
	<-mu.c
}

func (mu *tryLock) TryLock() bool {
	mu.once.Do(mu.init)
	select {
	case <-mu.c:
		return true
	default:
		return false
	}
}

func (mu *tryLock) Unlock() {
	mu.c <- struct{}{}
}

type lockedHost struct {
	reconnect func() error
	s         *proto.Session
	mu        tryLock
}

// A HostSet is a collection of renter-host protocol sessions.
type HostSet struct {
	sessions      map[hostdb.HostPublicKey]*lockedHost
	hkr           renter.HostKeyResolver
	currentHeight types.BlockHeight
	stats         proto.RPCStatsRecorder
	lockTimeout   time.Duration
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

func (set *HostSet) tryAcquire(host hostdb.HostPublicKey) (*proto.Session, error) {
	ls, ok := set.sessions[host]
	if !ok {
		return nil, errNoHost
	}
	if !ls.mu.TryLock() {
		return nil, errHostAcquired
	}
	if err := ls.reconnect(); err != nil {
		ls.mu.Unlock()
		return nil, err
	}
	return ls.s, nil
}

func (set *HostSet) release(host hostdb.HostPublicKey) {
	lh := set.sessions[host]
	if lh.s.IsClosed() {
		lh.s = nil // force a reconnect
	}
	lh.mu.Unlock()
}

// SetRPCStatsRecorder sets the RPCStatsRecorder for all Sessions initiated by
// the HostSet.
func (set *HostSet) SetRPCStatsRecorder(r proto.RPCStatsRecorder) { set.stats = r }

// SetLockTimeout sets the timeout used for all Lock RPCs in Sessions initiated
// by the HostSet.
func (set *HostSet) SetLockTimeout(timeout time.Duration) { set.lockTimeout = timeout }

// AddHost adds a host to the set for later use.
func (set *HostSet) AddHost(c renter.Contract) {
	lh := new(lockedHost)
	// lazy connection function
	var lastSeen time.Time
	lh.reconnect = func() error {
		defer func() { lastSeen = time.Now() }()
		if lh.s != nil {
			// if it hasn't been long since the last reconnect, assume the
			// connection is still open
			if time.Since(lastSeen) < 2*time.Minute {
				return nil
			}
			// otherwise, the connection *might* still be open; test by sending
			// a "ping" RPC
			//
			// NOTE: this is somewhat inefficient; it means we might incur an
			// extra roundtrip when we don't need to. Better would be for the
			// caller to handle the reconnection logic after calling whatever
			// RPC it wants to call; that way, we only do extra work if the host
			// has actually disconnected. But that feels too burdensome.
			if _, err := lh.s.Settings(); err == nil {
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
		// create and lock the session manually so that we can use our custom
		// lock timeout
		lh.s, err = proto.NewUnlockedSession(hostIP, c.HostKey, set.currentHeight)
		if err != nil {
			return err
		}
		if err := lh.s.Lock(c.ID, c.RenterKey, set.lockTimeout); err != nil {
			lh.s.Close()
			return err
		} else if _, err := lh.s.Settings(); err != nil {
			lh.s.Close()
			return err
		}
		lh.s.SetRPCStatsRecorder(set.stats)
		return nil
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
		lockTimeout:   10 * time.Second,
	}
}
