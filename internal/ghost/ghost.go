// Package ghost implements a barebones, ephemeral Sia host. It is used for
// testing purposes only, not hosting actual renter data on the Sia network.
package ghost

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/frand"
	"lukechampine.com/us/ed25519hash"
	"lukechampine.com/us/host"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renterhost"
)

// A Host is an ephemeral Sia host.
type Host struct {
	Settings  hostdb.HostSettings
	PublicKey hostdb.HostPublicKey
	l         net.Listener
	cm        *host.ChainManager
}

// Close closes the host's listener.
func (h *Host) Close() error {
	if h.l != nil {
		return h.l.Close()
	}
	return nil
}

// ProcessConsensusChange implements modules.ConsensusSetSubscriber.
func (h *Host) ProcessConsensusChange(cc modules.ConsensusChange) {
	h.cm.ProcessConsensusChange(cc)
}

// New returns an initialized host that listens for incoming sessions on a
// random localhost port. The host is automatically closed with tb.Cleanup.
func New(tb testing.TB, wallet host.Wallet, tpool host.TransactionPool) *Host {
	tb.Helper()
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { l.Close() })

	unlockHash, err := wallet.Address()
	if err != nil {
		tb.Fatal(err)
	}

	key := ed25519.NewKeyFromSeed(frand.Bytes(ed25519.SeedSize))
	settings := hostdb.HostSettings{
		AcceptingContracts:     true,
		NetAddress:             modules.NetAddress(l.Addr().String()),
		MaxDuration:            144,
		MaxCollateral:          types.SiacoinPrecision.Mul64(1e9),
		ContractPrice:          types.SiacoinPrecision,
		StoragePrice:           types.SiacoinPrecision.Div64(1e9),
		UploadBandwidthPrice:   types.SiacoinPrecision.Div64(2e9),
		DownloadBandwidthPrice: types.SiacoinPrecision.Div64(3e9),
		UnlockHash:             unlockHash,
		WindowSize:             5,
		Version:                "1.5.0",
	}
	store := newEphemeralContractStore()
	contracts := host.NewContractManager(key, store)
	storage := host.NewStorageManager(newEphemeralSectorStore())
	wm := host.NewWalletManager(wallet)
	cm := host.NewChainManager(store, tpool, wm, contracts, storage)
	sm := host.NewSessionManager(key, constantHostSettings(settings), contracts, storage, wm, cm)
	go sm.Listen(l)
	go cm.Watch()
	return &Host{
		Settings:  settings,
		PublicKey: hostdb.HostKeyFromPublicKey(ed25519hash.ExtractPublicKey(key)),
		l:         l,
		cm:        cm,
	}
}

type constantHostSettings hostdb.HostSettings

func (chs constantHostSettings) Settings() hostdb.HostSettings {
	return hostdb.HostSettings(chs)
}

type ephemeralSectorStore struct {
	sectors   map[crypto.Hash]*[renterhost.SectorSize]byte
	contracts map[types.FileContractID][]crypto.Hash
}

func (ess ephemeralSectorStore) Sector(root crypto.Hash) (*[renterhost.SectorSize]byte, error) {
	sector, ok := ess.sectors[root]
	if !ok {
		return nil, fmt.Errorf("no sector with Merkle root %v", root)
	}
	return sector, nil
}

func (ess ephemeralSectorStore) AddSector(root crypto.Hash, sector *[renterhost.SectorSize]byte) error {
	ess.sectors[root] = sector
	return nil
}

func (ess ephemeralSectorStore) DeleteSector(root crypto.Hash) error {
	delete(ess.sectors, root)
	return nil
}

func (ess ephemeralSectorStore) ContractRoots(id types.FileContractID) ([]crypto.Hash, error) {
	return ess.contracts[id], nil
}

func (ess ephemeralSectorStore) SetContractRoots(id types.FileContractID, roots []crypto.Hash) error {
	ess.contracts[id] = roots
	return nil
}

func newEphemeralSectorStore() ephemeralSectorStore {
	return ephemeralSectorStore{
		sectors:   make(map[crypto.Hash]*[renterhost.SectorSize]byte),
		contracts: make(map[types.FileContractID][]crypto.Hash),
	}
}

type ephemeralContractStore struct {
	contracts map[types.FileContractID]*host.Contract
	height    types.BlockHeight
	ccid      modules.ConsensusChangeID
	mu        sync.Mutex
}

func (ecs *ephemeralContractStore) ActionableContracts() ([]host.Contract, error) {
	ecs.mu.Lock()
	defer ecs.mu.Unlock()
	var contracts []host.Contract
	for _, c := range ecs.contracts {
		if host.ContractIsActionable(*c, ecs.height) {
			contracts = append(contracts, *c)
		}
	}
	return contracts, nil
}

func (ecs *ephemeralContractStore) Contract(id types.FileContractID) (host.Contract, error) {
	ecs.mu.Lock()
	defer ecs.mu.Unlock()
	c := ecs.contracts[id]
	if c == nil {
		return host.Contract{}, errors.New("no record of that contract")
	}
	return *c, nil
}

func (ecs *ephemeralContractStore) AddContract(c host.Contract) error {
	ecs.mu.Lock()
	defer ecs.mu.Unlock()
	ecs.contracts[c.ID()] = &c
	return nil
}

func (ecs *ephemeralContractStore) ApplyConsensusChange(reverted, applied host.ProcessedConsensusChange, ccid modules.ConsensusChangeID) error {
	ecs.mu.Lock()
	defer ecs.mu.Unlock()

	for _, id := range reverted.Contracts {
		if cc, ok := ecs.contracts[id]; ok {
			cc.FormationConfirmed = false
		}
	}
	for _, id := range reverted.Revisions {
		if cc, ok := ecs.contracts[id]; ok {
			cc.FinalizationConfirmed = false
		}
	}
	for _, id := range reverted.Proofs {
		if cc, ok := ecs.contracts[id]; ok {
			cc.ProofConfirmed = false
		}
	}
	for _, id := range applied.Contracts {
		if cc, ok := ecs.contracts[id]; ok {
			cc.FormationConfirmed = true
		}
	}
	for _, id := range applied.Revisions {
		if cc, ok := ecs.contracts[id]; ok {
			cc.FinalizationConfirmed = true
		}
	}
	for _, id := range applied.Proofs {
		if cc, ok := ecs.contracts[id]; ok {
			cc.ProofConfirmed = true
		}
	}
	ecs.height -= types.BlockHeight(len(reverted.BlockIDs))

	// adjust for genesis block (this should only ever be called once)
	if ecs.ccid == modules.ConsensusChangeBeginning {
		ecs.height--
	}

	for _, id := range applied.BlockIDs {
		ecs.height++
		for _, cc := range ecs.contracts {
			if cc.ProofHeight == ecs.height {
				rev := cc.FinalizationSet[len(cc.FinalizationSet)-1].FileContractRevisions[0]
				cc.ProofSegment = host.StorageProofSegment(id, rev.ParentID, rev.NewFileSize)
			}
		}
	}

	ecs.ccid = ccid
	return nil
}

func (ecs *ephemeralContractStore) ConsensusChangeID() modules.ConsensusChangeID {
	ecs.mu.Lock()
	defer ecs.mu.Unlock()
	return ecs.ccid
}

func (ecs *ephemeralContractStore) Height() types.BlockHeight {
	ecs.mu.Lock()
	defer ecs.mu.Unlock()
	return ecs.height
}

func newEphemeralContractStore() *ephemeralContractStore {
	return &ephemeralContractStore{
		contracts: make(map[types.FileContractID]*host.Contract),
	}
}
