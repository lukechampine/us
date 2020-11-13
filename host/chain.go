package host

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"math/bits"
	"strings"

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

// A ChainWatcher watches the blockchain and submits necessary contract
// transactions, including formations, renewals, revisions, and storage proofs.
type ChainWatcher struct {
	tpool     TransactionPool
	wallet    Wallet
	contracts ContractStore
	sectors   SectorStore

	watchChan chan struct{}
	stopChan  chan struct{}
}

// ProcessedConsensusChange is a filtered version of modules.ConsensusChange,
// containing only the information relevant to contract transactions.
type ProcessedConsensusChange struct {
	Contracts []types.FileContractID
	Revisions []types.FileContractID
	Proofs    []types.FileContractID
	BlockIDs  []types.BlockID
}

// ProcessConsensusChange implements modules.ConsensusSetSubscriber.
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
	cw.contracts.ApplyConsensusChange(reverted, applied, cc.ID)

	select {
	case cw.watchChan <- struct{}{}:
	default:
	}
}

// Announce creates, signs, and submits a host announcement transaction.
func (cw *ChainWatcher) Announce(addr modules.NetAddress, key ed25519.PrivateKey) error {
	_, feePerByte, err := cw.tpool.FeeEstimate()
	if err != nil {
		return err
	}
	txns, discard, err := announcementTransaction(addr, key, feePerByte, cw.wallet)
	if err != nil {
		return err
	}
	defer discard()
	return cw.submitTransaction(txns)
}

// StorageProofSegment returns the segment index for which a storage proof must
// be provided, given a contract and the block at the beginning of its proof
// window.
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

func (cw *ChainWatcher) submitTransaction(txns []types.Transaction) error {
	err := cw.tpool.AcceptTransactionSet(txns)
	if err == nil || err == modules.ErrDuplicateTransactionSet {
		return nil
	} else if strings.Contains(err.Error(), "transaction spends a nonexisting siacoin output") {
		return ErrMissingSiacoinOutput
	}
	return err
}

func (cw *ChainWatcher) finalizeContract(c Contract) ([]types.Transaction, func(), error) {
	_, feePerByte, err := cw.tpool.FeeEstimate()
	if err != nil {
		return nil, nil, err
	}
	return finalRevisionTransaction(c, feePerByte, cw.wallet)
}

func (cw *ChainWatcher) proveContract(c Contract) ([]types.Transaction, func(), error) {
	_, feePerByte, err := cw.tpool.FeeEstimate()
	if err != nil {
		return nil, nil, err
	}
	sp, err := buildStorageProof(c.ID(), c.ProofSegment, cw.sectors)
	if err != nil {
		return nil, nil, err
	}
	return storageProofTransaction(sp, feePerByte, cw.wallet)
}

func (cw *ChainWatcher) watchLoop() {
	defer close(cw.stopChan)
	for range cw.watchChan {
		for _, c := range cw.contracts.ActionableContracts() {
			switch {
			case !c.FormationConfirmed:
				c.FatalError = cw.submitTransaction(c.FormationSet)
			case !c.FinalizationConfirmed:
				txnSet, discard, err := cw.finalizeContract(c)
				if err != nil {
					c.FatalError = err
					continue
				}
				c.FatalError = cw.submitTransaction(txnSet)
				discard()
				if c.FatalError == nil {
					c.FinalizationSet = txnSet
				}
			case !c.ProofConfirmed:
				txnSet, discard, err := cw.proveContract(c)
				if err != nil {
					c.FatalError = err
					continue
				}
				c.FatalError = cw.submitTransaction(txnSet)
				discard()
				if c.FatalError == nil {
					c.ProofSet = txnSet
				}
			}
			cw.contracts.UpdateContractTransactions(c.ID(), c.FinalizationSet, c.ProofSet, c.FatalError)
		}
	}
}

// Close shuts down the ChainWatcher.
func (cw *ChainWatcher) Close() error {
	close(cw.watchChan)
	<-cw.stopChan
	return nil
}

// NewChainWatcher returns an initialized ChainWatcher.
func NewChainWatcher(tp TransactionPool, w Wallet, cs ContractStore, ss SectorStore) *ChainWatcher {
	cw := &ChainWatcher{
		tpool:     tp,
		wallet:    w,
		contracts: cs,
		sectors:   ss,
		watchChan: make(chan struct{}, 1),
		stopChan:  make(chan struct{}),
	}
	go cw.watchLoop()
	return cw
}
