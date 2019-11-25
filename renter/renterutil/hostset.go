package renterutil

import (
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
