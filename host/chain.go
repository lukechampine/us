package host

import (
	"encoding/binary"
	"math/bits"
	"strings"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"golang.org/x/crypto/blake2b"
	"lukechampine.com/us/merkle"
)

var (
	// ErrMissingSiacoinOutput is returned when a transaction spends an output that
	// is not in the UTXO set, either because it was created in a transaction not in
	// the blockchain (or transaction pool) or because it has already been spent.
	ErrMissingSiacoinOutput = errors.New("transaction spends a nonexisting siacoin output")
)

// ContractIsActionable returns true if any of a Contract's transactions are
// ready and have not been confirmed on chain.
func ContractIsActionable(c Contract, currentHeight types.BlockHeight) bool {
	return c.FatalError == nil && (!c.FormationConfirmed ||
		(!c.FinalizationConfirmed && currentHeight >= c.FinalizationHeight) ||
		(!c.ProofConfirmed && currentHeight >= c.ProofHeight))
}

// ChainManager ...
type ChainManager struct {
	store ContractStore
	tpool TransactionPool
	wmgr  *WalletManager
	cmgr  *ContractManager
	smgr  *StorageManager

	watchChan chan struct{}
}

// ProcessedConsensusChange ...
type ProcessedConsensusChange struct {
	Contracts []types.FileContractID
	Revisions []types.FileContractID
	Proofs    []types.FileContractID
	BlockIDs  []types.BlockID
}

// CurrentHeight ...
func (cm *ChainManager) CurrentHeight() types.BlockHeight {
	return cm.store.Height()
}

// MinFee ...
func (cm *ChainManager) MinFee() types.Currency {
	_, max, err := cm.tpool.FeeEstimate()
	if err != nil {
		max = types.SiacoinPrecision.Div64(1e3) // TODO: reasonable?
	}
	return max
}

// ProcessConsensusChange ...
func (cm *ChainManager) ProcessConsensusChange(cc modules.ConsensusChange) {
	process := func(blocks []types.Block) (pcc ProcessedConsensusChange) {
		for _, block := range blocks {
			for _, txn := range block.Transactions {
				for j := range txn.FileContracts {
					pcc.Contracts = append(pcc.Contracts, txn.FileContractID(uint64(j)))
				}
				for _, fcr := range txn.FileContractRevisions {
					pcc.Revisions = append(pcc.Revisions, fcr.ParentID)
				}
				for _, sp := range txn.StorageProofs {
					pcc.Proofs = append(pcc.Proofs, sp.ParentID)
				}
			}
			pcc.BlockIDs = append(pcc.BlockIDs, block.ID())
		}
		return
	}
	reverted := process(cc.RevertedBlocks)
	applied := process(cc.AppliedBlocks)
	if err := cm.store.ApplyConsensusChange(reverted, applied, cc.ID); err != nil {
		panic(err) // TODO
	}

	select {
	case cm.watchChan <- struct{}{}:
	default:
	}
}

// StorageProofSegment ...
//
// TODO: fuzz this
func StorageProofSegment(bid types.BlockID, fcid types.FileContractID, filesize uint64) uint64 {
	if filesize == 0 {
		return 0
	}
	seed := blake2b.Sum256(append(bid[:], fcid[:]...))
	numSegments := filesize / merkle.SegmentSize
	if filesize%merkle.SegmentSize != 0 {
		numSegments++
	}
	var r uint64
	for i := 0; i < 4; i++ {
		_, r = bits.Div64(r, binary.BigEndian.Uint64(seed[i*8:]), numSegments)
	}
	return r
}

// SuspendRevisionSubmission prevents the ChainManager from submitting the final
// revision transaction for the specified contract until
// ResumeRevisionSubmission is called.
func (cm *ChainManager) SuspendRevisionSubmission(id types.FileContractID) bool {
	return true
}

// ResumeRevisionSubmission lifts the suspension preventing the ChainManager
// from submitting the final revision transaction for the specified contract.
func (cm *ChainManager) ResumeRevisionSubmission(id types.FileContractID) {}

// BroadcastTransactionSet ...
func (cm *ChainManager) BroadcastTransactionSet(txns []types.Transaction) error {
	return cm.tpool.AcceptTransactionSet(txns)
}

func (cm *ChainManager) submitContractTxn(txns []types.Transaction) error {
	err := cm.tpool.AcceptTransactionSet(txns)
	if err == nil || err == modules.ErrDuplicateTransactionSet {
		return nil
	} else if strings.Contains(err.Error(), "transaction spends a nonexisting siacoin output") {
		return ErrMissingSiacoinOutput
	}
	return err
}

func (cm *ChainManager) finalizeContract(c Contract) ([]types.Transaction, error) {
	_, feePerByte, err := cm.tpool.FeeEstimate()
	if err != nil {
		return nil, err
	}
	if _, err = cm.cmgr.Acquire(c.ID(), 0); err != nil {
		return nil, err
	}
	return cm.wmgr.FinalRevisionTransaction(c, feePerByte)
}

func (cm *ChainManager) proveContract(c Contract) ([]types.Transaction, error) {
	_, feePerByte, err := cm.tpool.FeeEstimate()
	if err != nil {
		return nil, err
	}
	sp, err := cm.smgr.BuildStorageProof(c.ID(), c.ProofSegment)
	if err != nil {
		return nil, err
	}
	return cm.wmgr.StorageProofTransaction(sp, feePerByte)
}

// Watch ...
func (cm *ChainManager) Watch() {
	for range cm.watchChan {
		contracts, err := cm.store.ActionableContracts()
		if err != nil {
			panic(err) // TODO
		}

		for _, c := range contracts {
			switch {
			case !c.FormationConfirmed:
				if err := cm.submitContractTxn(c.FormationSet); err != nil {
					// all errors that occur when submitting the formation set
					// are fatal, since we can't change the renter's signatures
					c.FatalError = err
					if err := cm.store.AddContract(c); err != nil {
						panic(err) // TODO
					}
				}

			case !c.FinalizationConfirmed:
				if len(c.FinalizationSet) == 0 {
					c.FinalizationSet, err = cm.finalizeContract(c)
					if err != nil {
						// TODO: this error might be recoverable, e.g. if more
						// funds are added to the wallet
						c.FatalError = err
					}
					if err := cm.store.AddContract(c); err != nil {
						panic(err) // TODO
					}
				}
				if err := cm.submitContractTxn(c.FinalizationSet); err != nil {
					// TODO: ErrMissingSiacoinOutput is not fatal
					c.FatalError = err
					if err := cm.store.AddContract(c); err != nil {
						panic(err) // TODO
					}
				}

			case !c.ProofConfirmed:
				if len(c.ProofSet) == 0 {
					c.ProofSet, err = cm.proveContract(c)
					if err != nil {
						// TODO: this error might be recoverable, e.g. if more
						// funds are added to the wallet
						c.FatalError = err
					}
					if err := cm.store.AddContract(c); err != nil {
						panic(err) // TODO
					}
				}
				if err := cm.submitContractTxn(c.ProofSet); err != nil {
					// TODO: ErrMissingSiacoinOutput is not fatal
					c.FatalError = err
					if err := cm.store.AddContract(c); err != nil {
						panic(err) // TODO
					}
				}
			}
		}
	}
}

// NewChainManager returns an initialized chain manager.
func NewChainManager(store ContractStore, tpool TransactionPool, wmgr *WalletManager, cmgr *ContractManager, smgr *StorageManager) *ChainManager {
	return &ChainManager{
		store:     store,
		tpool:     tpool,
		wmgr:      wmgr,
		cmgr:      cmgr,
		smgr:      smgr,
		watchChan: make(chan struct{}, 1),
	}
}
