package main

import (
	"os"
	"sort"
	"strings"
	"sync"

	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
)

type consensusSet interface {
	ConsensusSetSubscribe(modules.ConsensusSetSubscriber, modules.ConsensusChangeID, <-chan struct{}) error
	Synced() bool
}

type SHARD struct {
	height     types.BlockHeight
	hosts      map[string][]byte // pubkey -> announcement
	hostKeys   []string          // sorted
	lastChange modules.ConsensusChangeID
	queuedSave bool
	cs         consensusSet
	persist    persister
	mu         sync.Mutex
}

func (s *SHARD) Synced() bool {
	return s.cs.Synced()
}

func (s *SHARD) Height() types.BlockHeight {
	s.mu.Lock()
	height := s.height
	s.mu.Unlock()
	return height
}

func (s *SHARD) Host(prefix string) (pk string, unique bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.hosts[prefix]; ok {
		return prefix, true
	}
	i := sort.Search(len(s.hostKeys), func(i int) bool {
		hk := s.hostKeys[i]
		if len(prefix) > len(hk) {
			return hk[:len(prefix)] >= prefix
		}
		return hk[:len(prefix)] >= prefix
	})
	if i == len(s.hostKeys) || !strings.HasPrefix(s.hostKeys[i], prefix) {
		return "", false
	}
	pk = s.hostKeys[i]
	unique = i+1 == len(s.hostKeys) || !strings.HasPrefix(s.hostKeys[i+1], prefix)
	return
}

func (s *SHARD) HostAnnouncement(pubkey string) ([]byte, bool) {
	s.mu.Lock()
	ann, ok := s.hosts[pubkey]
	s.mu.Unlock()
	return ann, ok
}

func newSHARD(cs consensusSet, p persister) (*SHARD, error) {
	s := &SHARD{
		hosts:   make(map[string][]byte),
		cs:      cs,
		persist: p,
	}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	// subscribe to consensus
	if err := cs.ConsensusSetSubscribe(s, s.lastChange, nil); err != nil {
		s.lastChange = modules.ConsensusChangeBeginning
		if err := cs.ConsensusSetSubscribe(s, s.lastChange, nil); err != nil {
			return nil, err
		}
	}
	return s, nil
}
