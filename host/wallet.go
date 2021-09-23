package host

import (
	"crypto/ed25519"

	"go.sia.tech/siad/crypto"
	"go.sia.tech/siad/modules"
	"go.sia.tech/siad/types"
	"gitlab.com/NebulousLabs/encoding"
	"golang.org/x/crypto/blake2b"
	"lukechampine.com/us/ed25519hash"
	"lukechampine.com/us/renterhost"
)

func fundTransaction(txn *types.Transaction, cost types.Currency, w Wallet, tp TransactionPool) (renterhost.RPCFormContractAdditions, func(), error) {
	if cost.IsZero() {
		return renterhost.RPCFormContractAdditions{}, nil, nil
	}
	oldInputs, oldOutputs := len(txn.SiacoinInputs), len(txn.SiacoinOutputs)
	_, discard, err := w.FundTransaction(txn, cost)
	if err != nil {
		return renterhost.RPCFormContractAdditions{}, nil, err
	}
	parents, err := tp.UnconfirmedParents(*txn)
	if err != nil {
		discard()
		return renterhost.RPCFormContractAdditions{}, nil, err
	}
	return renterhost.RPCFormContractAdditions{
		Parents: parents,
		Inputs:  txn.SiacoinInputs[oldInputs:],
		Outputs: txn.SiacoinOutputs[oldOutputs:],
	}, discard, nil
}

func fundContractTransaction(cb *contractBuilder, w Wallet, tp TransactionPool) (err error) {
	cost := cb.contract.ValidHostPayout().Sub(cb.settings.ContractPrice) // NOTE: validateFormContract prevents underflow here
	cb.hostAdditions, cb.discard, err = fundTransaction(&cb.transaction, cost, w, tp)
	cb.parents = append(cb.parents, cb.hostAdditions.Parents...)
	return
}

func fundRenewalTransaction(cb *contractBuilder, w Wallet, tp TransactionPool) (err error) {
	var basePrice types.Currency
	if cb.contract.WindowEnd > cb.finalRevision.NewWindowEnd {
		timeExtension := uint64(cb.contract.WindowEnd - cb.finalRevision.NewWindowEnd)
		basePrice = cb.settings.StoragePrice.Mul64(cb.contract.FileSize).Mul64(timeExtension)
	}
	cost := cb.contract.ValidHostPayout().Sub(cb.settings.ContractPrice).Sub(basePrice) // NOTE: validateRenewContract prevents underflow here
	cb.hostAdditions, cb.discard, err = fundTransaction(&cb.transaction, cost, w, tp)
	cb.parents = append(cb.parents, cb.hostAdditions.Parents...)
	return
}

func signTransaction(txn *types.Transaction, inputs []types.SiacoinInput, w Wallet) ([]types.TransactionSignature, error) {
	// NOTE: it is important that we do not blindly sign all inputs we control;
	// if a malicious renter knows which inputs we control, they could trick us
	// into paying for our own contract!
	toSign := make([]crypto.Hash, len(inputs))
	for i, in := range inputs {
		toSign[i] = crypto.Hash(in.ParentID)
	}
	err := w.SignTransaction(txn, toSign)
	return txn.TransactionSignatures[len(txn.TransactionSignatures)-len(toSign):], err
}

func finalizeSimpleTxn(txn types.Transaction, w Wallet) ([]types.Transaction, func(), error) {
	toSign, discard, err := w.FundTransaction(&txn, txn.SiacoinOutputSum())
	if err != nil {
		return nil, nil, err
	} else if err := w.SignTransaction(&txn, toSign); err != nil {
		discard()
		return nil, nil, err
	}
	return []types.Transaction{txn}, discard, nil
}

func finalRevisionTransaction(c Contract, feePerByte types.Currency, w Wallet) ([]types.Transaction, func(), error) {
	const estTxnSize = 2048
	return finalizeSimpleTxn(types.Transaction{
		FileContractRevisions: []types.FileContractRevision{c.Revision},
		TransactionSignatures: c.Signatures[:],
		MinerFees:             []types.Currency{feePerByte.Mul64(estTxnSize)},
	}, w)
}

func storageProofTransaction(sp types.StorageProof, feePerByte types.Currency, w Wallet) ([]types.Transaction, func(), error) {
	// TODO: A transaction containing a storage proof is not allowed to contain
	// any other type of output, which means we can't include a typical change
	// output; instead, we must construct a parent transaction that creates an
	// output worth exactly as much as the fee. For now, we just submit a proof
	// transaction with no fee.
	return []types.Transaction{{
		StorageProofs: []types.StorageProof{sp},
	}}, func() {}, nil
}

func announcementTransaction(addr modules.NetAddress, key ed25519.PrivateKey, feePerByte types.Currency, w Wallet) ([]types.Transaction, func(), error) {
	const estTxnSize = 2048
	ann := encoding.MarshalAll(modules.PrefixHostAnnouncement, addr, types.SiaPublicKey{
		Algorithm: types.SignatureEd25519,
		Key:       ed25519hash.ExtractPublicKey(key),
	})
	return finalizeSimpleTxn(types.Transaction{
		ArbitraryData: [][]byte{append(ann, ed25519hash.Sign(key, blake2b.Sum256(ann))...)},
		MinerFees:     []types.Currency{feePerByte.Mul64(estTxnSize)},
	}, w)
}
