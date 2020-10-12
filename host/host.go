// Package host implements a Sia hosting framework.
package host

import (
	"crypto/ed25519"
	"time"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renterhost"
)

// ContractStore ...
type ContractStore interface {
	SigningKey() ed25519.PrivateKey
	Contract(id types.FileContractID) (Contract, error)
	AddContract(c Contract) error
	ReviseContract(rev types.FileContractRevision, renterSig, hostSig []byte) error
	ActionableContracts() ([]Contract, error)
	ApplyConsensusChange(reverted, applied ProcessedConsensusChange, ccid modules.ConsensusChangeID) error
	ConsensusChangeID() modules.ConsensusChangeID
	Height() types.BlockHeight
}

// SectorStore ...
type SectorStore interface {
	AddSector(root crypto.Hash, sector *[renterhost.SectorSize]byte) error
	ContractRoots(id types.FileContractID) ([]crypto.Hash, error)
	DeleteSector(root crypto.Hash) error
	Sector(root crypto.Hash) (*[renterhost.SectorSize]byte, error)
	SetContractRoots(id types.FileContractID, roots []crypto.Hash) error
}

// A Wallet provides addresses and outputs, and can sign transactions.
type Wallet interface {
	Address() (types.UnlockHash, error)
	FundTransaction(txn *types.Transaction, cost types.Currency) ([]crypto.Hash, error)
	SignTransaction(txn *types.Transaction, toSign []crypto.Hash) error
}

// SettingsReporter ...
type SettingsReporter interface {
	Settings() hostdb.HostSettings
}

// TransactionPool ...
type TransactionPool interface {
	AcceptTransactionSet([]types.Transaction) error
	FeeEstimate() (min, max types.Currency, err error)
}

// Contract ...
type Contract struct {
	Revision   types.FileContractRevision
	Signatures [2]types.TransactionSignature

	FormationSet    []types.Transaction
	FinalizationSet []types.Transaction
	ProofSet        []types.Transaction

	FormationConfirmed    bool
	FinalizationConfirmed bool
	ProofConfirmed        bool

	FinalizationHeight types.BlockHeight
	ProofHeight        types.BlockHeight
	ProofSegment       uint64

	// Non-nil, with explanatory error message, if it is no longer possible to
	// submit a valid storage proof for the Contract.
	FatalError error
}

// ID is a helper method that returns the contract's ID.
func (c *Contract) ID() types.FileContractID {
	return c.Revision.ParentID
}

// RenterKey ...
func (c *Contract) RenterKey() types.SiaPublicKey {
	return c.Revision.UnlockConditions.PublicKeys[0]
}

// MetricsRecorder ...
type MetricsRecorder interface {
	RecordSessionMetric(ctx *SessionContext, m Metric)
}

// SessionContext ...
type SessionContext struct {
	UID       [16]byte
	RenterIP  string
	Timestamp time.Time
	Elapsed   time.Duration
	UpBytes   uint64
	DownBytes uint64

	Contract types.FileContractRevision
	Settings hostdb.HostSettings
}

// Metric ...
type Metric interface {
	isMetric()
}

func (MetricHandshake) isMetric()  {}
func (MetricSessionEnd) isMetric() {}
func (MetricRPCStart) isMetric()   {}
func (MetricRPCEnd) isMetric()     {}

// MetricHandshake ...
type MetricHandshake struct {
	Err error
}

// MetricSessionEnd ...
type MetricSessionEnd struct {
	Err error
}

// MetricRPCStart ...
type MetricRPCStart struct {
	ID        renterhost.Specifier
	Timestamp time.Time
}

// MetricRPCEnd ...
type MetricRPCEnd struct {
	ID        renterhost.Specifier
	Elapsed   time.Duration
	UpBytes   uint64
	DownBytes uint64
	Err       error
}
