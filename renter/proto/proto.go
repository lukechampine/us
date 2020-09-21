// Package proto implements the renter side of the Sia renter-host protocol.
package proto // import "lukechampine.com/us/renter/proto"

import (
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renterhost"
)

func wrapErr(err *error, fnName string) {
	*err = errors.WithMessage(*err, fnName)
}

func wrapErrWithReplace(err *error, fnName string) {
	if *err != nil {
		*err = errors.Wrap(errors.Unwrap(*err), fnName)
	}
}

// A Wallet provides addresses and outputs, and can sign transactions.
type Wallet interface {
	Address() (types.UnlockHash, error)
	FundTransaction(txn *types.Transaction, amount types.Currency) ([]crypto.Hash, error)
	SignTransaction(txn *types.Transaction, toSign []crypto.Hash) error
}

// A TransactionPool can broadcast transactions and estimate transaction
// fees.
type TransactionPool interface {
	AcceptTransactionSet(txnSet []types.Transaction) error
	UnconfirmedParents(txn types.Transaction) ([]types.Transaction, error)
	FeeEstimate() (min types.Currency, max types.Currency, err error)
}

// RPCStats contains various statistics related to an RPC.
type RPCStats struct {
	Host     hostdb.HostPublicKey
	Contract types.FileContractID // empty if no contract is locked
	RPC      renterhost.Specifier
	// Timestamp is the moment the RPC method was invoked; likewise, Elapsed is
	// measured at the moment the RPC method returns. Consequently, these stats
	// do *not* enable direct measurement of host throughput. However, stats may
	// be compared *across* hosts in order to rank their relative performance.
	Timestamp  time.Time
	Elapsed    time.Duration
	Err        error
	Uploaded   uint64
	Downloaded uint64
	Cost       types.Currency
}

// A RPCStatsRecorder records RPCStats, as reported by a Session.
type RPCStatsRecorder interface {
	RecordRPCStats(stats RPCStats)
}

// A ContractRevision contains the most recent revision to a file contract and
// its signatures.
type ContractRevision struct {
	Revision   types.FileContractRevision
	Signatures [2]types.TransactionSignature
}

// EndHeight returns the height at which the host is no longer obligated to
// store contract data.
func (c ContractRevision) EndHeight() types.BlockHeight {
	return c.Revision.NewWindowStart
}

// ID returns the ID of the original FileContract.
func (c ContractRevision) ID() types.FileContractID {
	return c.Revision.ParentID
}

// HostKey returns the public key of the host.
func (c ContractRevision) HostKey() hostdb.HostPublicKey {
	return hostdb.HostKeyFromSiaPublicKey(c.Revision.UnlockConditions.PublicKeys[1])
}

// RenterFunds returns the funds remaining in the contract's Renter payout.
func (c ContractRevision) RenterFunds() types.Currency {
	return c.Revision.NewValidProofOutputs[0].Value
}

// NumSectors returns the number of sectors covered by the contract.
func (c ContractRevision) NumSectors() int {
	return int(c.Revision.NewFileSize / renterhost.SectorSize)
}

// IsValid returns false if the ContractRevision has the wrong number of
// public keys or outputs.
func (c ContractRevision) IsValid() bool {
	return len(c.Revision.NewValidProofOutputs) > 0 &&
		len(c.Revision.UnlockConditions.PublicKeys) == 2
}

// SubmitContractRevision submits the latest revision of a contract to the
// blockchain, finalizing the renter and host payouts as they stand in the
// revision. Submitting a revision with a higher revision number will replace
// the previously-submitted revision.
//
// Submitting revision transactions is a way for the renter to punish the
// host. If the host is well-behaved, there is no incentive for the renter to
// submit revision transactions. But if the host misbehaves, submitting the
// revision ensures that the host will lose the collateral it committed.
func SubmitContractRevision(c ContractRevision, w Wallet, tpool TransactionPool) (err error) {
	defer wrapErr(&err, "SubmitContractRevision")

	// calculate transaction fee
	_, maxFee, err := tpool.FeeEstimate()
	if err != nil {
		return errors.Wrap(err, "could not estimate transaction fee")
	}
	fee := maxFee.Mul64(estTxnSize)

	// construct a transaction containing the signed revision
	txn := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{c.Revision},
		MinerFees:             []types.Currency{fee},
		TransactionSignatures: c.Signatures[:],
	}

	// pay for the fee
	if toSign, err := w.FundTransaction(&txn, fee); err != nil {
		return err
	} else if err := w.SignTransaction(&txn, toSign); err != nil {
		return errors.Wrap(err, "failed to sign transaction")
	}

	// submit the funded and signed transaction
	if err := tpool.AcceptTransactionSet([]types.Transaction{txn}); err != nil {
		return err
	}
	return nil
}
