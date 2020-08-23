package host

import (
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/renterhost"
)

// WalletManager ...
type WalletManager struct {
	wallet Wallet
}

func (wm *WalletManager) fundTransaction(txn *types.Transaction, cost types.Currency) (renterhost.RPCFormContractAdditions, error) {
	if cost.IsZero() {
		return renterhost.RPCFormContractAdditions{}, nil
	}
	oldInputs, oldOutputs := len(txn.SiacoinInputs), len(txn.SiacoinOutputs)
	if _, err := wm.wallet.FundTransaction(txn, cost); err != nil {
		return renterhost.RPCFormContractAdditions{}, err
	}
	return renterhost.RPCFormContractAdditions{
		Inputs:  txn.SiacoinInputs[oldInputs:],
		Outputs: txn.SiacoinOutputs[oldOutputs:],
	}, nil
}

// FundContract ...
func (wm *WalletManager) FundContract(cb *contractBuilder) (err error) {
	cost := cb.contract.ValidHostPayout().Sub(cb.settings.ContractPrice) // NOTE: ConsiderFormRequest prevents underflow here
	cb.hostAdditions, err = wm.fundTransaction(&cb.transaction, cost)
	return
}

// FundRenewal ...
func (wm *WalletManager) FundRenewal(cb *contractBuilder) (err error) {
	var basePrice types.Currency
	if cb.contract.WindowEnd > cb.finalRevision.NewWindowEnd {
		timeExtension := uint64(cb.contract.WindowEnd - cb.finalRevision.NewWindowEnd)
		basePrice = cb.settings.StoragePrice.Mul64(cb.contract.FileSize).Mul64(timeExtension)
	}
	cost := cb.contract.ValidHostPayout().Sub(cb.settings.ContractPrice).Sub(basePrice) // NOTE: ConsiderRenewRequest prevents underflow here
	cb.hostAdditions, err = wm.fundTransaction(&cb.transaction, cost)
	return
}

func (wm *WalletManager) signTransaction(txn *types.Transaction, inputs []types.SiacoinInput) ([]types.TransactionSignature, error) {
	// NOTE: it is important that we do not blindly sign all inputs we control;
	// if a malicious renter knows which inputs we control, they could trick us
	// into paying for our own contract!
	toSign := make([]crypto.Hash, len(inputs))
	for i, in := range inputs {
		toSign[i] = crypto.Hash(in.ParentID)
	}
	err := wm.wallet.SignTransaction(txn, toSign)
	return txn.TransactionSignatures[len(txn.TransactionSignatures)-len(toSign):], err
}

// SignContract ...
func (wm *WalletManager) SignContract(cb *contractBuilder) (err error) {
	cb.transaction.TransactionSignatures = append(cb.transaction.TransactionSignatures, cb.renterSigs.ContractSignatures...)
	cb.hostSigs.ContractSignatures, err = wm.signTransaction(&cb.transaction, cb.hostAdditions.Inputs)
	return
}

// SignRenewal ...
func (wm *WalletManager) SignRenewal(cb *contractBuilder) (err error) {
	cb.transaction.TransactionSignatures = append(cb.transaction.TransactionSignatures, cb.renterRenewSigs.ContractSignatures...)
	cb.hostRenewSigs.ContractSignatures, err = wm.signTransaction(&cb.transaction, cb.hostAdditions.Inputs)
	return
}

func (wm *WalletManager) finalizeSimpleTxn(txn types.Transaction) ([]types.Transaction, error) {
	if toSign, err := wm.wallet.FundTransaction(&txn, txn.SiacoinOutputSum()); err != nil {
		return nil, err
	} else if err := wm.wallet.SignTransaction(&txn, toSign); err != nil {
		return nil, err
	}
	return []types.Transaction{txn}, nil
}

// AnnouncementTransaction ...
func (wm *WalletManager) AnnouncementTransaction(announcement []byte, feePerByte types.Currency) ([]types.Transaction, error) {
	const estTxnSize = 2048
	return wm.finalizeSimpleTxn(types.Transaction{
		ArbitraryData: [][]byte{announcement},
		MinerFees:     []types.Currency{feePerByte.Mul64(estTxnSize)},
	})
}

// FinalRevisionTransaction ...
func (wm *WalletManager) FinalRevisionTransaction(c Contract, feePerByte types.Currency) ([]types.Transaction, error) {
	const estTxnSize = 2048
	return wm.finalizeSimpleTxn(types.Transaction{
		FileContractRevisions: []types.FileContractRevision{c.Revision},
		TransactionSignatures: c.Signatures[:],
		MinerFees:             []types.Currency{feePerByte.Mul64(estTxnSize)},
	})
}

// StorageProofTransaction ...
func (wm *WalletManager) StorageProofTransaction(sp types.StorageProof, feePerByte types.Currency) ([]types.Transaction, error) {
	// TODO: A transaction containing a storage proof is not allowed to contain
	// any other type of output, which means we can't include a typical change
	// output; instead, we must construct a parent transaction that creates an
	// output worth exactly as much as the fee. For now, we just submit a proof
	// transaction with no fee.
	return []types.Transaction{{
		StorageProofs: []types.StorageProof{sp},
	}}, nil
}

// NewWalletManager returns an initialized wallet manager.
func NewWalletManager(wallet Wallet) *WalletManager {
	return &WalletManager{
		wallet: wallet,
	}
}
