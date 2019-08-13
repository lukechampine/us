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

	// ignore "ephemeral" outputs (outputs created and spent in the same
	// ConsensusChange).
	survivingOutputs := make(map[types.SiacoinOutputID]struct{})
	for _, diff := range cc.SiacoinOutputDiffs {
		if _, ok := survivingOutputs[diff.ID]; !ok {
			survivingOutputs[diff.ID] = struct{}{}
		} else {
			delete(survivingOutputs, diff.ID)
		}
	}
	processOutput := func(diff modules.SiacoinOutputDiff, pcc *ProcessedConsensusChange) {
		if _, ok := survivingOutputs[diff.ID]; ok && cs.Owner.OwnsAddress(diff.SiacoinOutput.UnlockHash) {
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
	// NOTE: we do not process the DelayedSiacoinOutputDiffs in the same way as
	// above, for two reasons. First, they don't carry enough information (e.g.
	// for a BlockReward, we might want to know the ID of the block); second,
	// they are "reverted" when they expire *or* are invalidated, whereas we
	// want to continue storing block rewards/file contracts indefinitely and
	// only revert them if they are invalidated.

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

				for i, fc := range txn.FileContracts {
					if cs.relevantFileContract(fc.ValidProofOutputs, fc.MissedProofOutputs) {
						pcc.FileContracts = append(pcc.FileContracts, FileContract{
							FileContract:     fc,
							UnlockConditions: types.UnlockConditions{}, // unknown
							ID:               txn.FileContractID(uint64(i)),
						})
					}
				}
				for _, fcr := range txn.FileContractRevisions {
					if cs.relevantFileContract(fcr.NewValidProofOutputs, fcr.NewMissedProofOutputs) {
						// locate payout in cc (FileContractRevision doesn't
						// contain the Payout field)
						//
						// NOTE: we don't want to take the entire FileContract
						// from cc.FileContractDiffs, because it's hard to be
						// sure that we'd be taking the correct revision (since
						// the diff aggregates across all blocks in the cc).
						var payout types.Currency
						for _, diff := range cc.FileContractDiffs {
							if diff.ID == fcr.ParentID {
								payout = diff.FileContract.Payout
								break
							}
						}
						pcc.FileContracts = append(pcc.FileContracts, FileContract{
							FileContract: types.FileContract{
								FileSize:           fcr.NewFileSize,
								FileMerkleRoot:     fcr.NewFileMerkleRoot,
								WindowStart:        fcr.NewWindowStart,
								WindowEnd:          fcr.NewWindowEnd,
								Payout:             payout,
								ValidProofOutputs:  fcr.NewValidProofOutputs,
								MissedProofOutputs: fcr.NewMissedProofOutputs,
								UnlockHash:         fcr.NewUnlockHash,
								RevisionNumber:     fcr.NewRevisionNumber,
							},
							UnlockConditions: fcr.UnlockConditions,
							ID:               fcr.ParentID,
						})
					}
				}
			}
		}
	}
	processMinerPayouts := func(b types.Block, pcc *ProcessedConsensusChange) {
		for i, mp := range b.MinerPayouts {
			if cs.Owner.OwnsAddress(mp.UnlockHash) {
				// locate in DSCOs
				id := b.MinerPayoutID(uint64(i))
				for _, diff := range cc.DelayedSiacoinOutputDiffs {
					if diff.ID == id {
						pcc.BlockRewards = append(pcc.BlockRewards, BlockReward{
							UnspentOutput: UnspentOutput{
								SiacoinOutput: diff.SiacoinOutput,
								ID:            id,
							},
							Timelock: diff.MaturityHeight,
						})
						break
					}
				}
			}
		}
	}

	for _, b := range cc.AppliedBlocks {
		processTxns(b.Transactions, &applied)
		processMinerPayouts(b, &applied)
	}
	for _, b := range cc.RevertedBlocks {
		processTxns(b.Transactions, &reverted)
		processMinerPayouts(b, &reverted)
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
		processAddr(CalculateUnlockHash(txn.SiacoinInputs[i].UnlockConditions))
	}
	for i := range txn.SiacoinOutputs {
		processAddr(txn.SiacoinOutputs[i].UnlockHash)
	}
	for i := range txn.SiafundInputs {
		processAddr(CalculateUnlockHash(txn.SiafundInputs[i].UnlockConditions))
		processAddr(txn.SiafundInputs[i].ClaimUnlockHash)
	}
	for i := range txn.SiafundOutputs {
		processAddr(txn.SiafundOutputs[i].UnlockHash)
	}
	for i := range txn.FileContracts {
		for _, sco := range txn.FileContracts[i].ValidProofOutputs {
			processAddr(sco.UnlockHash)
		}
		for _, sco := range txn.FileContracts[i].MissedProofOutputs {
			processAddr(sco.UnlockHash)
		}
	}
	for i := range txn.FileContractRevisions {
		for _, sco := range txn.FileContractRevisions[i].NewValidProofOutputs {
			processAddr(sco.UnlockHash)
		}
		for _, sco := range txn.FileContractRevisions[i].NewMissedProofOutputs {
			processAddr(sco.UnlockHash)
		}
	}
	return addrs
}

func (cs *ChainScanner) relevantFileContract(valid, missed []types.SiacoinOutput) bool {
	relevant := false
	for _, sco := range valid {
		relevant = relevant || cs.Owner.OwnsAddress(sco.UnlockHash)
	}
	for _, sco := range missed {
		relevant = relevant || cs.Owner.OwnsAddress(sco.UnlockHash)
	}
	return relevant
}
