// Package proto implements the Sia renter-host protocol.
package proto // import "lukechampine.com/us/renter/proto"

import (
	"github.com/NebulousLabs/Sia/crypto"
	"github.com/NebulousLabs/Sia/encoding"
	"github.com/NebulousLabs/Sia/modules"
	"github.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/hostdb"

	"github.com/pkg/errors"
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

// SubmitContractTransaction submits the latest revision of a contract to the
// blockchain, finalizing the renter and host payouts as they stand in the
// revision. Submitting a revision with a higher revision number will replace
// the previously-submitted revision.
//
// Submitting revision transactions is a way for the renter to punish the
// host. If the host is well-behaved, there is no incentive for the renter to
// submit revision transactions. But if the host misbehaves, submitting the
// revision ensures that the host will lose the collateral it committed.
func SubmitContractTransaction(c ContractTransaction, w Wallet, tpool TransactionPool) error {
	// make a copy of the transaction. In practice it's probably fine to
	// modify the transaction directly (since we'd be appending to the slices,
	// leaving the original unchanged) but we might as well be cautious.
	var txn types.Transaction
	encoding.Unmarshal(encoding.Marshal(c.Transaction), &txn)

	// add the transaction fee
	_, maxFee := tpool.FeeEstimate()
	fee := maxFee.Mul64(estTxnSize)
	txn.MinerFees = append(txn.MinerFees, fee)

	// pay for the fee by adding outputs and signing them
	outputs := w.SpendableOutputs()
	changeAddr, err := w.NewWalletAddress()
	if err != nil {
		return errors.Wrap(err, "could not get a change address to use")
	}
	toSign, ok := fundSiacoins(&txn, outputs, fee, changeAddr)
	if !ok {
		return errors.New("not enough coins to fund transaction fee")
	}
	if err := w.SignTransaction(&txn, toSign); err != nil {
		return errors.Wrap(err, "failed to sign transaction")
	}

	// submit the funded and signed transaction
	if err := tpool.AcceptTransactionSet([]types.Transaction{txn}); err != nil {
		return err
	}
	return nil
}
