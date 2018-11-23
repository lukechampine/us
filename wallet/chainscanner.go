package wallet

import (
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
)

// A ChainScanner scans the blockchain for outputs and transactions relevant to
// Owner and stores them in Store. Relevance is determined as follows: an output
// is relevant if its UnlockHash is owned by the AddressOwner; a transaction is
// relevant if any of the UnlockHashes or UnlockConditions appearing in it are
// owned by the AddressOwner.
type ChainScanner struct {
	Owner AddressOwner
	Store ChainStore
}

// ProcessConsensusChange implements modules.ConsensusSetSubscriber.
func (cs ChainScanner) ProcessConsensusChange(cc modules.ConsensusChange) {
	var reverted, applied ProcessedConsensusChange

	processOutput := func(diff modules.SiacoinOutputDiff, pcc *ProcessedConsensusChange) {
		if cs.Owner.OwnsAddress(diff.SiacoinOutput.UnlockHash) {
			pcc.Outputs = append(pcc.Outputs, UnspentOutput{
				SiacoinOutput: diff.SiacoinOutput,
				ID:            diff.ID,
			})
		}
	}
	for _, diff := range cc.SiacoinOutputDiffs {
		if diff.Direction == modules.DiffApply {
			processOutput(diff, &applied)
		} else {
			processOutput(diff, &reverted)
		}
	}

	processTxns := func(txns []types.Transaction, pcc *ProcessedConsensusChange) {
		for _, txn := range txns {
			if addrs := cs.relevantTxn(txn); len(addrs) > 0 {
				if pcc.AddressTransactions == nil {
					pcc.AddressTransactions = make(map[types.UnlockHash][]types.TransactionID)
				}
				txid := txn.ID()
				for addr := range addrs {
					pcc.AddressTransactions[addr] = append(pcc.AddressTransactions[addr], txid)
				}
				pcc.Transactions = append(pcc.Transactions, txn)
			}
		}
	}
	for _, b := range cc.AppliedBlocks {
		processTxns(b.Transactions, &applied)
	}
	for _, b := range cc.RevertedBlocks {
		processTxns(b.Transactions, &reverted)
	}
	applied.BlockCount = len(cc.AppliedBlocks)
	reverted.BlockCount = len(cc.RevertedBlocks)

	cs.Store.ApplyConsensusChange(reverted, applied, cc.ID)
}

func (cs *ChainScanner) relevantTxn(txn types.Transaction) map[types.UnlockHash]struct{} {
	addrs := make(map[types.UnlockHash]struct{})
	processAddr := func(addr types.UnlockHash) {
		if _, ok := addrs[addr]; !ok && cs.Owner.OwnsAddress(addr) {
			addrs[addr] = struct{}{}
		}
	}
	for i := range txn.SiacoinInputs {
		processAddr(txn.SiacoinInputs[i].UnlockConditions.UnlockHash())
	}
	for i := range txn.SiacoinOutputs {
		processAddr(txn.SiacoinOutputs[i].UnlockHash)
	}
	for i := range txn.SiafundInputs {
		processAddr(txn.SiafundInputs[i].UnlockConditions.UnlockHash())
		processAddr(txn.SiafundInputs[i].ClaimUnlockHash)
	}
	for i := range txn.SiafundOutputs {
		processAddr(txn.SiafundOutputs[i].UnlockHash)
	}
	for i := range txn.FileContracts {
		processAddr(txn.FileContracts[i].UnlockHash)
	}
	for i := range txn.FileContractRevisions {
		processAddr(txn.FileContractRevisions[i].NewUnlockHash)
		processAddr(txn.FileContractRevisions[i].UnlockConditions.UnlockHash())
	}
	return addrs
}
