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
		(!c.FinalizationConfirmed && currentHeight >= c.FinalizationHeight && c.Revision.NewRevisionNumber > 1) ||
		(!c.ProofConfirmed && currentHeight >= c.ProofHeight && c.Revision.NewFileSize > 0))
}

func minFee(tp TransactionPool) types.Currency {
	_, max, err := tp.FeeEstimate()
	if err != nil {
		max = types.SiacoinPrecision.Div64(1e3) // TODO: reasonable?
	}
	return max
}

// ChainWatcher ...
type ChainWatcher struct {
	tpool     TransactionPool
	wallet    Wallet
	contracts ContractStore
	sectors   SectorStore

	watchChan chan struct{}
	stopChan  chan struct{}
}

// ProcessedConsensusChange ...
type ProcessedConsensusChange struct {
	Contracts []types.FileContractID
	Revisions []types.FileContractID
	Proofs    []types.FileContractID
	BlockIDs  []types.BlockID
}

// ProcessConsensusChange ...
func (cw *ChainWatcher) ProcessConsensusChange(cc modules.ConsensusChange) {
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
	if err := cw.contracts.ApplyConsensusChange(reverted, applied, cc.ID); err != nil {
		panic(err) // TODO
	}

	select {
	case cw.watchChan <- struct{}{}:
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

// SuspendRevisionSubmission prevents the ChainWatcher from submitting the final
// revision transaction for the specified contract until
// ResumeRevisionSubmission is called.
func (cw *ChainWatcher) SuspendRevisionSubmission(id types.FileContractID) bool {
	return true
}

// ResumeRevisionSubmission lifts the suspension preventing the ChainWatcher
// from submitting the final revision transaction for the specified contract.
func (cw *ChainWatcher) ResumeRevisionSubmission(id types.FileContractID) {}

func (cw *ChainWatcher) submitTransaction(txns []types.Transaction) error {
	err := cw.tpool.AcceptTransactionSet(txns)
	if err == nil || err == modules.ErrDuplicateTransactionSet {
		return nil
	} else if strings.Contains(err.Error(), "transaction spends a nonexisting siacoin output") {
		return ErrMissingSiacoinOutput
	}
	return err
}

func (cw *ChainWatcher) finalizeContract(c Contract) ([]types.Transaction, error) {
	_, feePerByte, err := cw.tpool.FeeEstimate()
	if err != nil {
		return nil, err
	}
	return finalRevisionTransaction(c, feePerByte, cw.wallet)
}

func (cw *ChainWatcher) proveContract(c Contract) ([]types.Transaction, error) {
	_, feePerByte, err := cw.tpool.FeeEstimate()
	if err != nil {
		return nil, err
	}
	sp, err := buildStorageProof(c.ID(), c.ProofSegment, cw.sectors)
	if err != nil {
		return nil, err
	}
	return storageProofTransaction(sp, feePerByte, cw.wallet)
}

// Watch ...
func (cw *ChainWatcher) Watch() {
	for range cw.watchChan {
		contracts, err := cw.contracts.ActionableContracts()
		if err != nil {
			panic(err) // TODO
		}

		for _, c := range contracts {
			switch {
			case !c.FormationConfirmed:
				if err := cw.submitTransaction(c.FormationSet); err != nil {
					// all errors that occur when submitting the formation set
					// are fatal, since we can't change the renter's signatures
					c.FatalError = err
					if err := cw.contracts.AddContract(c); err != nil {
						panic(err) // TODO
					}
				}

			case !c.FinalizationConfirmed:
				if len(c.FinalizationSet) == 0 {
					c.FinalizationSet, err = cw.finalizeContract(c)
					if err != nil {
						// TODO: this error might be recoverable, e.g. if more
						// funds are added to the wallet
						c.FatalError = err
					}
					if err := cw.contracts.AddContract(c); err != nil {
						panic(err) // TODO
					}
				}
				if err := cw.submitTransaction(c.FinalizationSet); err != nil {
					// TODO: ErrMissingSiacoinOutput is not fatal
					c.FatalError = err
					if err := cw.contracts.AddContract(c); err != nil {
						panic(err) // TODO
					}
				}

			case !c.ProofConfirmed:
				if len(c.ProofSet) == 0 {
					c.ProofSet, err = cw.proveContract(c)
					if err != nil {
						// TODO: this error might be recoverable, e.g. if more
						// funds are added to the wallet
						c.FatalError = err
					}
					if err := cw.contracts.AddContract(c); err != nil {
						panic(err) // TODO
					}
				}
				if err := cw.submitTransaction(c.ProofSet); err != nil {
					// TODO: ErrMissingSiacoinOutput is not fatal
					c.FatalError = err
					if err := cw.contracts.AddContract(c); err != nil {
						panic(err) // TODO
					}
				}
			}
		}
	}
	close(cw.stopChan)
}

// Close shuts down the ChainWatcher.
func (cw *ChainWatcher) Close() error {
	close(cw.watchChan)
	<-cw.stopChan
	return nil
}

// NewChainWatcher returns an initialized ChainWatcher.
func NewChainWatcher(tp TransactionPool, w Wallet, cs ContractStore, ss SectorStore) *ChainWatcher {
	return &ChainWatcher{
		tpool:     tp,
		wallet:    w,
		contracts: cs,
		sectors:   ss,
		watchChan: make(chan struct{}, 1),
		stopChan:  make(chan struct{}),
	}
}
