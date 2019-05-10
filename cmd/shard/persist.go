package main

import (
	"os"
	"path/filepath"
	"sort"

	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/persist"
	"gitlab.com/NebulousLabs/Sia/types"
)

type shardPersist struct {
	Height     types.BlockHeight
	Hosts      map[string][]byte
	LastChange modules.ConsensusChangeID
}

type persister interface {
	save(shardPersist) error
	load(*shardPersist) error
}

func (s *SHARD) save() error {
	return s.persist.save(shardPersist{
		Height:     s.height,
		Hosts:      s.hosts,
		LastChange: s.lastChange,
	})
}

func (s *SHARD) load() error {
	var data shardPersist
	if err := s.persist.load(&data); err != nil && !os.IsNotExist(err) {
		return err
	}
	if data.Hosts == nil {
		data.Hosts = make(map[string][]byte)
	}
	s.height = data.Height
	s.hosts = data.Hosts
	s.lastChange = data.LastChange
	for pk := range s.hosts {
		s.hostKeys = append(s.hostKeys, pk)
	}
	sort.Strings(s.hostKeys)
	return nil
}

var meta = persist.Metadata{
	Header:  "shard",
	Version: "0.1.0",
}

type jsonPersist struct {
	path string
}

func (p jsonPersist) save(data shardPersist) error {
	return persist.SaveJSON(meta, data, p.path)
}

func (p jsonPersist) load(data *shardPersist) error {
	return persist.LoadJSON(meta, data, p.path)
}

func newJSONPersist(dir string) jsonPersist {
	return jsonPersist{filepath.Join(dir, "persist.json")}
}
