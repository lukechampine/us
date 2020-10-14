package host

import (
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/renterhost"
)

func fundTransaction(txn *types.Transaction, cost types.Currency, w Wallet) (renterhost.RPCFormContractAdditions, error) {
	if cost.IsZero() {
		return renterhost.RPCFormContractAdditions{}, nil
	}
	oldInputs, oldOutputs := len(txn.SiacoinInputs), len(txn.SiacoinOutputs)
	if _, err := w.FundTransaction(txn, cost); err != nil {
		return renterhost.RPCFormContractAdditions{}, err
	}
	return renterhost.RPCFormContractAdditions{
		Inputs:  txn.SiacoinInputs[oldInputs:],
		Outputs: txn.SiacoinOutputs[oldOutputs:],
	}, nil
}

func fundContractTransaction(cb *contractBuilder, w Wallet) (err error) {
	cost := cb.contract.ValidHostPayout().Sub(cb.settings.ContractPrice) // NOTE: validateFormContract prevents underflow here
	cb.hostAdditions, err = fundTransaction(&cb.transaction, cost, w)
	return
}

func fundRenewalTransaction(cb *contractBuilder, w Wallet) (err error) {
	var basePrice types.Currency
	if cb.contract.WindowEnd > cb.finalRevision.NewWindowEnd {
		timeExtension := uint64(cb.contract.WindowEnd - cb.finalRevision.NewWindowEnd)
		basePrice = cb.settings.StoragePrice.Mul64(cb.contract.FileSize).Mul64(timeExtension)
	}
	cost := cb.contract.ValidHostPayout().Sub(cb.settings.ContractPrice).Sub(basePrice) // NOTE: validateRenewContract prevents underflow here
	cb.hostAdditions, err = fundTransaction(&cb.transaction, cost, w)
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

func finalizeSimpleTxn(txn types.Transaction, w Wallet) ([]types.Transaction, error) {
	if toSign, err := w.FundTransaction(&txn, txn.SiacoinOutputSum()); err != nil {
		return nil, err
	} else if err := w.SignTransaction(&txn, toSign); err != nil {
		return nil, err
	}
	return []types.Transaction{txn}, nil
}

func announcementTransaction(announcement []byte, feePerByte types.Currency, w Wallet) ([]types.Transaction, error) {
	const estTxnSize = 2048
	return finalizeSimpleTxn(types.Transaction{
		ArbitraryData: [][]byte{announcement},
		MinerFees:     []types.Currency{feePerByte.Mul64(estTxnSize)},
	}, w)
}

func finalRevisionTransaction(c Contract, feePerByte types.Currency, w Wallet) ([]types.Transaction, error) {
	const estTxnSize = 2048
	return finalizeSimpleTxn(types.Transaction{
		FileContractRevisions: []types.FileContractRevision{c.Revision},
		TransactionSignatures: c.Signatures[:],
		MinerFees:             []types.Currency{feePerByte.Mul64(estTxnSize)},
	}, w)
}

func storageProofTransaction(sp types.StorageProof, feePerByte types.Currency, w Wallet) ([]types.Transaction, error) {
	// TODO: A transaction containing a storage proof is not allowed to contain
	// any other type of output, which means we can't include a typical change
	// output; instead, we must construct a parent transaction that creates an
	// output worth exactly as much as the fee. For now, we just submit a proof
	// transaction with no fee.
	return []types.Transaction{{
		StorageProofs: []types.StorageProof{sp},
	}}, nil
}