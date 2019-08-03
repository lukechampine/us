package wallet

import (
	"time"

	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
)

// EphemeralStore implements Store in-memory.
type EphemeralStore struct {
	outputs       map[types.SiacoinOutputID]UnspentOutput
	blockrewards  []BlockReward
	filecontracts []FileContract

	txns            map[types.TransactionID]types.Transaction
	limbo           map[types.TransactionID]LimboTransaction
	txnsAddrIndex   map[types.UnlockHash][]types.TransactionID
	txnsRecentIndex []types.TransactionID
	memos           map[types.TransactionID][]byte

	height int
	ccid   modules.ConsensusChangeID
}

// ApplyConsensusChange implements ChainStore.
func (s *EphemeralStore) ApplyConsensusChange(reverted, applied ProcessedConsensusChange, ccid modules.ConsensusChangeID) {
	for _, o := range reverted.Outputs {
		delete(s.outputs, o.ID)
	}
	for _, br := range reverted.BlockRewards {
		for i := range s.blockrewards {
			if s.blockrewards[i].ID == br.ID {
				s.blockrewards = append(s.blockrewards[:i], s.blockrewards[i+1:]...)
				break
			}
		}
	}
	for _, fc := range reverted.FileContracts {
		for i := range s.filecontracts {
			if s.filecontracts[i].ID == fc.ID && s.filecontracts[i].RevisionNumber == fc.RevisionNumber {
				s.filecontracts = append(s.filecontracts[:i], s.filecontracts[i+1:]...)
				break
			}
		}
	}

	for _, txn := range reverted.Transactions {
		txid := txn.ID()
		delete(s.txns, txid)
		delete(s.limbo, txid)
		for i := range s.txnsRecentIndex {
			if s.txnsRecentIndex[i] == txid {
				s.txnsRecentIndex = append(s.txnsRecentIndex[:i], s.txnsRecentIndex[i+1:]...)
				break
			}
		}
	}
	for addr, txids := range reverted.AddressTransactions {
		addrTxns := s.txnsAddrIndex[addr]
		for _, txid := range txids {
			for i := range addrTxns {
				if addrTxns[i] == txid {
					addrTxns = append(addrTxns[:i], addrTxns[i+1:]...)
					break
				}
			}
		}
		s.txnsAddrIndex[addr] = addrTxns
	}
	for _, o := range applied.Outputs {
		s.outputs[o.ID] = o
	}
	s.blockrewards = append(s.blockrewards, applied.BlockRewards...)
	s.filecontracts = append(s.filecontracts, applied.FileContracts...)
	for _, txn := range applied.Transactions {
		txid := txn.ID()
		s.txns[txid] = txn
		delete(s.limbo, txid)
		s.txnsRecentIndex = append(s.txnsRecentIndex, txid)
	}
	for addr, txids := range applied.AddressTransactions {
		s.txnsAddrIndex[addr] = append(s.txnsAddrIndex[addr], txids...)
	}

	s.height += applied.BlockCount - reverted.BlockCount
	s.ccid = ccid
}

// UnspentOutputs implements Store.
func (s *EphemeralStore) UnspentOutputs() []UnspentOutput {
	outputs := make([]UnspentOutput, 0, len(s.outputs))
	for _, o := range s.outputs {
		outputs = append(outputs, o)
	}
	return outputs
}

// Transactions implements Store.
func (s *EphemeralStore) Transactions(n int) []types.TransactionID {
	if n > len(s.txnsRecentIndex) || n < 0 {
		n = len(s.txnsRecentIndex)
	}
	return s.txnsRecentIndex[len(s.txnsRecentIndex)-n:]
}

// TransactionsByAddress implements Store.
func (s *EphemeralStore) TransactionsByAddress(addr types.UnlockHash, n int) []types.TransactionID {
	txns := s.txnsAddrIndex[addr]
	if n > len(txns) || n < 0 {
		n = len(txns)
	}
	return txns[len(txns)-n:]
}

// Transaction implements Store.
func (s *EphemeralStore) Transaction(id types.TransactionID) (types.Transaction, bool) {
	txn, ok := s.txns[id]
	return txn, ok
}

// AddToLimbo implements Store.
func (s *EphemeralStore) AddToLimbo(txn types.Transaction) {
	txid := txn.ID()
	if _, ok := s.limbo[txid]; ok {
		return // don't overwrite older LimboSince
	}
	s.limbo[txn.ID()] = LimboTransaction{
		Transaction: txn,
		LimboSince:  time.Now(),
	}
}

// RemoveFromLimbo implements Store.
func (s *EphemeralStore) RemoveFromLimbo(id types.TransactionID) {
	delete(s.limbo, id)
}

// LimboTransactions implements Store.
func (s *EphemeralStore) LimboTransactions() []LimboTransaction {
	txns := make([]LimboTransaction, 0, len(s.limbo))
	for _, txn := range s.limbo {
		txns = append(txns, txn)
	}
	return txns
}

// BlockRewards implements Store.
func (s *EphemeralStore) BlockRewards(n int) []BlockReward {
	if n > len(s.blockrewards) || n < 0 {
		n = len(s.blockrewards)
	}
	return s.blockrewards[len(s.blockrewards)-n:]
}

// FileContracts implements Store.
func (s *EphemeralStore) FileContracts(n int) []FileContract {
	if n > len(s.filecontracts) || n < 0 {
		n = len(s.filecontracts)
	}
	return s.filecontracts[len(s.filecontracts)-n:]
}

// FileContractHistory implements Store.
func (s *EphemeralStore) FileContractHistory(id types.FileContractID) []FileContract {
	var history []FileContract
	for _, fc := range s.filecontracts {
		if fc.ID == id {
			history = append(history, fc)
		}
	}
	return history
}

// SetMemo implements Store.
func (s *EphemeralStore) SetMemo(txid types.TransactionID, memo []byte) {
	s.memos[txid] = append([]byte(nil), memo...)
}

// Memo implements Store.
func (s *EphemeralStore) Memo(txid types.TransactionID) []byte {
	return append([]byte(nil), s.memos[txid]...)
}

// ChainHeight implements Store.
func (s *EphemeralStore) ChainHeight() types.BlockHeight {
	height := types.BlockHeight(s.height)
	if height > 0 {
		height-- // adjust for genesis block
	}
	return height
}

// ConsensusChangeID implements Store.
func (s *EphemeralStore) ConsensusChangeID() modules.ConsensusChangeID {
	return s.ccid
}

// NewEphemeralStore returns a new EphemeralStore.
func NewEphemeralStore() *EphemeralStore {
	return &EphemeralStore{
		outputs:       make(map[types.SiacoinOutputID]UnspentOutput),
		txns:          make(map[types.TransactionID]types.Transaction),
		limbo:         make(map[types.TransactionID]LimboTransaction),
		txnsAddrIndex: make(map[types.UnlockHash][]types.TransactionID),
		memos:         make(map[types.TransactionID][]byte),
	}
}

// EphemeralSeedStore implements SeedStore in-memory.
type EphemeralSeedStore struct {
	EphemeralStore
	seedIndex uint64
}

// SeedIndex implements SeedStore.
func (s *EphemeralSeedStore) SeedIndex() uint64 {
	return s.seedIndex
}

// SetSeedIndex implements SeedStore.
func (s *EphemeralSeedStore) SetSeedIndex(index uint64) {
	s.seedIndex = index
}

// NewEphemeralSeedStore returns a new EphemeralSeedStore.
func NewEphemeralSeedStore() *EphemeralSeedStore {
	return &EphemeralSeedStore{
		EphemeralStore: *NewEphemeralStore(),
	}
}

// EphemeralWatchOnlyStore implements WatchOnlyStore in-memory.
type EphemeralWatchOnlyStore struct {
	EphemeralStore
	addrs map[types.UnlockHash][]byte
}

// OwnsAddress implements WatchOnlyStore.
func (s *EphemeralWatchOnlyStore) OwnsAddress(addr types.UnlockHash) bool {
	_, ok := s.addrs[addr]
	return ok
}

// AddAddress implements WatchOnlyStore.
func (s *EphemeralWatchOnlyStore) AddAddress(addr types.UnlockHash, info []byte) {
	s.addrs[addr] = append([]byte(nil), info...)
}

// AddressInfo implements WatchOnlyStore.
func (s *EphemeralWatchOnlyStore) AddressInfo(addr types.UnlockHash) (info []byte) {
	return append(info, s.addrs[addr]...)
}

// RemoveAddress implements WatchOnlyStore.
func (s *EphemeralWatchOnlyStore) RemoveAddress(addr types.UnlockHash) {
	delete(s.addrs, addr)
}

// Addresses implements WatchOnlyStore.
func (s *EphemeralWatchOnlyStore) Addresses() []types.UnlockHash {
	addrs := make([]types.UnlockHash, 0, len(s.addrs))
	for addr := range s.addrs {
		addrs = append(addrs, addr)
	}
	return addrs
}

// NewEphemeralWatchOnlyStore returns a new EphemeralWatchOnlyStore.
func NewEphemeralWatchOnlyStore() *EphemeralWatchOnlyStore {
	return &EphemeralWatchOnlyStore{
		EphemeralStore: *NewEphemeralStore(),
		addrs:          make(map[types.UnlockHash][]byte),
	}
}
