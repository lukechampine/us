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

// DefaultSettings are the default (cheap) ghost settings.
var DefaultSettings = hostdb.HostSettings{
	AcceptingContracts:     true,
	MaxDuration:            144,
	MaxCollateral:          types.SiacoinPrecision.Mul64(1e9),
	ContractPrice:          types.SiacoinPrecision,
	StoragePrice:           types.SiacoinPrecision.Div64(1e9),
	UploadBandwidthPrice:   types.SiacoinPrecision.Div64(2e9),
	DownloadBandwidthPrice: types.SiacoinPrecision.Div64(3e9),
	WindowSize:             5,
	Version:                "1.5.0",
	Make:                   "ghost",
	Model:                  "v0.1.0",
}

// FreeSettings are the cheapest possible ghost settings.
var FreeSettings = hostdb.HostSettings{
	AcceptingContracts:     true,
	MaxDuration:            144,
	MaxCollateral:          types.NewCurrency64(1),
	ContractPrice:          types.ZeroCurrency,
	StoragePrice:           types.ZeroCurrency,
	UploadBandwidthPrice:   types.ZeroCurrency,
	DownloadBandwidthPrice: types.ZeroCurrency,
	WindowSize:             5,
	Version:                "1.5.0",
	Make:                   "ghost",
	Model:                  "v0.1.0",
}

// A Host is an ephemeral Sia host.
type Host struct {
	Settings  hostdb.HostSettings
	PublicKey hostdb.HostPublicKey
	l         net.Listener
	cw        *host.ChainWatcher
}

// Close closes the host's listener.
func (h *Host) Close() error {
	if h.l == nil {
		return nil
	}
	h.l.Close()
	h.cw.Close()
	h.l = nil
	return nil
}

// ProcessConsensusChange implements modules.ConsensusSetSubscriber.
func (h *Host) ProcessConsensusChange(cc modules.ConsensusChange) {
	h.cw.ProcessConsensusChange(cc)
}

// New returns an initialized host that listens for incoming sessions on a
// random localhost port. The host is automatically closed with tb.Cleanup.
func New(tb testing.TB, settings hostdb.HostSettings, wm host.Wallet, tpool host.TransactionPool) *Host {
	tb.Helper()
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { l.Close() })
	settings.NetAddress = modules.NetAddress(l.Addr().String())
	settings.UnlockHash, err = wm.Address()
	if err != nil {
		tb.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(frand.Bytes(ed25519.SeedSize))
	h := &Host{
		PublicKey: hostdb.HostKeyFromPublicKey(ed25519hash.ExtractPublicKey(key)),
		Settings:  settings,
		l:         l,
	}
	cs := newEphemeralContractStore(key)
	ss := newEphemeralSectorStore()
	sm := host.NewSessionHandler(key, (*constantHostSettings)(&h.Settings), cs, ss, wm, tpool, nopMetricsRecorder{})
	go sm.Listen(l)
	h.cw = host.NewChainWatcher(tpool, wm, cs, ss)
	go h.cw.Watch()
	return h
}

type constantHostSettings hostdb.HostSettings

func (chs *constantHostSettings) Settings() hostdb.HostSettings {
	return hostdb.HostSettings(*chs)
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
	key       ed25519.PrivateKey
	contracts map[types.FileContractID]*host.Contract
	height    types.BlockHeight
	ccid      modules.ConsensusChangeID
	mu        sync.Mutex
}

func (ecm *ephemeralContractStore) SigningKey() ed25519.PrivateKey {
	return ecm.key
}

func (ecm *ephemeralContractStore) ActionableContracts() ([]host.Contract, error) {
	ecm.mu.Lock()
	defer ecm.mu.Unlock()
	var contracts []host.Contract
	for _, c := range ecm.contracts {
		if host.ContractIsActionable(*c, ecm.height) {
			contracts = append(contracts, *c)
		}
	}
	return contracts, nil
}

func (ecm *ephemeralContractStore) Contract(id types.FileContractID) (host.Contract, error) {
	ecm.mu.Lock()
	defer ecm.mu.Unlock()
	c := ecm.contracts[id]
	if c == nil {
		return host.Contract{}, errors.New("no record of that contract")
	}
	return *c, nil
}

func (ecm *ephemeralContractStore) AddContract(c host.Contract) error {
	ecm.mu.Lock()
	defer ecm.mu.Unlock()
	ecm.contracts[c.ID()] = &c
	return nil
}

func (ecm *ephemeralContractStore) ReviseContract(rev types.FileContractRevision, renterSig, hostSig []byte) error {
	ecm.mu.Lock()
	defer ecm.mu.Unlock()
	c, ok := ecm.contracts[rev.ID()]
	if !ok {
		return errors.New("no record of that contract")
	}
	c.Revision = rev
	c.Signatures[0].Signature = renterSig
	c.Signatures[1].Signature = hostSig
	return nil
}

func (ecm *ephemeralContractStore) ApplyConsensusChange(reverted, applied host.ProcessedConsensusChange, ccid modules.ConsensusChangeID) error {
	ecm.mu.Lock()
	defer ecm.mu.Unlock()

	for _, id := range reverted.Contracts {
		if cc, ok := ecm.contracts[id]; ok {
			cc.FormationConfirmed = false
		}
	}
	for _, id := range reverted.Revisions {
		if cc, ok := ecm.contracts[id]; ok {
			cc.FinalizationConfirmed = false
		}
	}
	for _, id := range reverted.Proofs {
		if cc, ok := ecm.contracts[id]; ok {
			cc.ProofConfirmed = false
		}
	}
	for _, id := range applied.Contracts {
		if cc, ok := ecm.contracts[id]; ok {
			cc.FormationConfirmed = true
		}
	}
	for _, id := range applied.Revisions {
		if cc, ok := ecm.contracts[id]; ok {
			cc.FinalizationConfirmed = true
		}
	}
	for _, id := range applied.Proofs {
		if cc, ok := ecm.contracts[id]; ok {
			cc.ProofConfirmed = true
		}
	}
	ecm.height -= types.BlockHeight(len(reverted.BlockIDs))

	// adjust for genesis block (this should only ever be called once)
	if ecm.ccid == modules.ConsensusChangeBeginning {
		ecm.height--
	}

	for _, id := range applied.BlockIDs {
		ecm.height++
		for _, cc := range ecm.contracts {
			if cc.ProofHeight == ecm.height && len(cc.FinalizationSet) > 0 {
				rev := cc.FinalizationSet[len(cc.FinalizationSet)-1].FileContractRevisions[0]
				cc.ProofSegment = host.StorageProofSegment(id, rev.ParentID, rev.NewFileSize)
			}
		}
	}

	// mark contracts as failed if their formation transaction is not confirmed
	// within 6 blocks
	for _, c := range ecm.contracts {
		if c.FatalError == nil && !c.FormationConfirmed && ecm.height > c.FormationHeight+6 {
			c.FatalError = errors.New("contract formation transaction was not confirmed on blockchain")
		}
	}

	ecm.ccid = ccid
	return nil
}

func (ecm *ephemeralContractStore) ConsensusChangeID() modules.ConsensusChangeID {
	ecm.mu.Lock()
	defer ecm.mu.Unlock()
	return ecm.ccid
}

func (ecm *ephemeralContractStore) Height() types.BlockHeight {
	ecm.mu.Lock()
	defer ecm.mu.Unlock()
	return ecm.height
}

func newEphemeralContractStore(key ed25519.PrivateKey) *ephemeralContractStore {
	return &ephemeralContractStore{
		key:       key,
		contracts: make(map[types.FileContractID]*host.Contract),
	}
}

type nopMetricsRecorder struct{}

func (nopMetricsRecorder) RecordSessionMetric(ctx *host.SessionContext, m host.Metric) {}
