// Package proto implements the renter side of the Sia renter-host protocol.
package proto // import "lukechampine.com/us/renter/proto"

import (
	"errors"
	"fmt"
	"time"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renterhost"
)

func wrapErr(err *error, fnName string) {
	if *err != nil {
		*err = fmt.Errorf("%s: %w", fnName, *err)
	}
}

func wrapErrWithReplace(err *error, fnName string) {
	if *err != nil {
		*err = fmt.Errorf("%s: %w", fnName, errors.Unwrap(*err))
	}
}

// A Wallet provides addresses and outputs, and can sign transactions.
type Wallet interface {
	// Address returns an address controlled by the wallet.
	Address() (types.UnlockHash, error)
	// FundTransaction adds inputs to txn worth at least amount, adding a change
	// output if needed. It returns the added input IDs, for use with
	// SignTransaction. It also returns a function that will "unclaim" the
	// inputs; this function must be called once the transaction has been
	// broadcast or discarded.
	FundTransaction(txn *types.Transaction, amount types.Currency) ([]crypto.Hash, func(), error)
	// SignTransaction signs the specified transaction using keys derived from the
	// wallet seed. If toSign is nil, SignTransaction will automatically add
	// TransactionSignatures for each input owned by the seed. If toSign is not nil,
	// it a list of indices of TransactionSignatures already present in txn;
	// SignTransaction will fill in the Signature field of each.
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
		return fmt.Errorf("could not estimate transaction fee: %w", err)
	}
	fee := maxFee.Mul64(estTxnSize)

	// construct a transaction containing the signed revision
	txn := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{c.Revision},
		MinerFees:             []types.Currency{fee},
		TransactionSignatures: c.Signatures[:],
	}

	// pay for the fee
	toSign, discard, err := w.FundTransaction(&txn, fee)
	if err != nil {
		return err
	}
	defer discard()
	if err := w.SignTransaction(&txn, toSign); err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	// submit the funded and signed transaction
	if err := tpool.AcceptTransactionSet([]types.Transaction{txn}); err != nil {
		return err
	}
	return nil
}
