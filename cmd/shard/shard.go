package main

import (
	"os"
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
