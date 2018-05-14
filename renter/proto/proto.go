// Package proto implements the Sia renter-host protocol.
package proto

import (
	"encoding/json"
	"errors"
	"unsafe"

	"github.com/lukechampine/us/hostdb"

	"github.com/NebulousLabs/Sia/crypto"
	"github.com/NebulousLabs/Sia/modules"
	"github.com/NebulousLabs/Sia/types"
)

// ErrDesynchronized is returned by ContractEditor.SyncWithHost to indicate
// that synchronization is impossible.
var ErrDesynchronized = errors.New("renter contract has permanently desynchronized from host")

type (
	// A Wallet provides addresses and outputs, and can sign transactions.
	Wallet interface {
		NewWalletAddress() (types.UnlockHash, error)
		SignTransaction(txn *types.Transaction, toSign map[types.OutputID]types.UnlockHash) error
		SpendableOutputs() []modules.SpendableOutput
	}
	// A TransactionPool can broadcast transactions and estimate transaction
	// fees.
	TransactionPool interface {
		AcceptTransactionSet([]types.Transaction) error
		FeeEstimate() (min types.Currency, max types.Currency)
	}
)

// A ContractEditor provides an interface for viewing and updating a file
// contract transaction and the Merkle roots of each sector covered by the
// contract.
type ContractEditor interface {
	// Transaction returns the transaction containing the latest revision of
	// the file contract.
	Transaction() ContractTransaction

	// Revise sets the latest revision of the contract.
	Revise(rev types.FileContractRevision) error

	// AppendRoot appends a sector root to the contract, returning the new
	// top-level Merkle root. The root should be written to durable storage.
	AppendRoot(root crypto.Hash) (crypto.Hash, error)

	// NumSectors returns the number of sector roots in the contract.
	NumSectors() int

	// SyncWithHost synchronizes the local version of the contract with the
	// host's version. This may involve modifying the sector roots and/or
	// contract revision. SyncWithHost returns ErrDesynchronized iff the
	// contract has permanently desynchronized with the host and recovery is
	// impossible.
	SyncWithHost(rev types.FileContractRevision, hostSignatures []types.TransactionSignature) error
}

// A ContractTransaction contains a file contract transaction and the secret
// key used to sign it.
type ContractTransaction struct {
	Transaction types.Transaction
	RenterKey   crypto.SecretKey
}

// CurrentRevision returns the most recently negotiated revision of the
// original FileContract.
func (c ContractTransaction) CurrentRevision() types.FileContractRevision {
	return c.Transaction.FileContractRevisions[0]
}

// EndHeight returns the height at which the host is no longer obligated to
// store contract data.
func (c ContractTransaction) EndHeight() types.BlockHeight {
	return c.CurrentRevision().NewWindowStart
}

// ID returns the ID of the original FileContract.
func (c ContractTransaction) ID() types.FileContractID {
	return c.CurrentRevision().ParentID
}

// HostKey returns the public key of the host.
func (c ContractTransaction) HostKey() hostdb.HostPublicKey {
	key := c.CurrentRevision().UnlockConditions.PublicKeys[1]
	return hostdb.HostPublicKey(key.String())
}

// RenterFunds returns the funds remaining in the contract's Renter payout as
// of the most recent revision.
func (c ContractTransaction) RenterFunds() types.Currency {
	return c.CurrentRevision().NewValidProofOutputs[0].Value
}

// IsValid returns false if the Contract does not contain a
// FileContractRevision, or contains a FileContractRevision without the proper
// number of outputs.
func (c ContractTransaction) IsValid() bool {
	return len(c.Transaction.FileContractRevisions) > 0 &&
		len(c.Transaction.FileContractRevisions[0].NewValidProofOutputs) > 0 &&
		len(c.Transaction.FileContractRevisions[0].UnlockConditions.PublicKeys) == 2
}

// helper types for encoding ContractTransactions more efficiently (omitting
// empty fields in Transaction and encoding RenterKey as base64 rather than an
// array of numbers).
type (
	encodedContract struct {
		Transaction encodedTransaction `json:"transaction"`
		RenterKey   []byte             `json:"renterKey"`
	}
	encodedTransaction struct {
		SiacoinInputs         []types.SiacoinInput         `json:"siacoinInputs,omitempty"`
		SiacoinOutputs        []types.SiacoinOutput        `json:"siacoinOutputs,omitempty"`
		FileContracts         []types.FileContract         `json:"fileContracts,omitempty"`
		FileContractRevisions []types.FileContractRevision `json:"fileContractRevisions,omitempty"`
		StorageProofs         []types.StorageProof         `json:"storageProofs,omitempty"`
		SiafundInputs         []types.SiafundInput         `json:"siafundInputs,omitempty"`
		SiafundOutputs        []types.SiafundOutput        `json:"siafundOutputs,omitempty"`
		MinerFees             []types.Currency             `json:"minerFees,omitempty"`
		ArbitraryData         [][]byte                     `json:"arbitraryData,omitempty"`
		TransactionSignatures []struct {
			ParentID       crypto.Hash       `json:"parentID"`
			PublicKeyIndex uint64            `json:"publicKeyIndex"`
			Timelock       types.BlockHeight `json:"timelock,omitempty"`
			CoveredFields  struct {
				WholeTransaction      bool     `json:"wholeTransaction,omitempty"`
				SiacoinInputs         []uint64 `json:"siacoinInputs,omitempty"`
				SiacoinOutputs        []uint64 `json:"siacoinOutputs,omitempty"`
				FileContracts         []uint64 `json:"fileContracts,omitempty"`
				FileContractRevisions []uint64 `json:"fileContractRevisions,omitempty"`
				StorageProofs         []uint64 `json:"storageProofs,omitempty"`
				SiafundInputs         []uint64 `json:"siafundInputs,omitempty"`
				SiafundOutputs        []uint64 `json:"siafundOutputs,omitempty"`
				MinerFees             []uint64 `json:"minerFees,omitempty"`
				ArbitraryData         []uint64 `json:"arbitraryData,omitempty"`
				TransactionSignatures []uint64 `json:"transactionSignatures,omitempty"`
			} `json:"coveredFields"`
			Signature []byte `json:"signature"`
		} `json:"transactionSignatures,omitempty"`
	}
)

// MarshalJSON implements the json.Marshaler interface.
func (c ContractTransaction) MarshalJSON() ([]byte, error) {
	return json.Marshal(encodedContract{
		Transaction: *(*encodedTransaction)(unsafe.Pointer(&c.Transaction)),
		RenterKey:   c.RenterKey[:],
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (c *ContractTransaction) UnmarshalJSON(b []byte) error {
	var ec encodedContract
	err := json.Unmarshal(b, &ec)
	if err != nil {
		return err
	}
	c.Transaction = *(*types.Transaction)(unsafe.Pointer(&ec.Transaction))
	copy(c.RenterKey[:], ec.RenterKey)
	return nil
}
