package wallet

import (
	"time"

	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
)

// EphemeralStore implements Store in-memory.
type EphemeralStore struct {
	outputs map[types.SiacoinOutputID]LimboOutput

	txns            map[types.TransactionID]types.Transaction
	txnsAddrIndex   map[types.UnlockHash][]types.TransactionID
	txnsRecentIndex []types.TransactionID
	memos           map[types.TransactionID][]byte

	height int
	ccid   modules.ConsensusChangeID
}

// ApplyConsensusChange implements Store.
func (s *EphemeralStore) ApplyConsensusChange(reverted, applied ProcessedConsensusChange, ccid modules.ConsensusChangeID) {
	for _, o := range reverted.Outputs {
		delete(s.outputs, o.ID)
	}
	for _, txn := range reverted.Transactions {
		txid := txn.ID()
		delete(s.txns, txid)
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
		s.outputs[o.ID] = LimboOutput{
			UnspentOutput: o,
			LimboSince:    notLimboTime,
		}
	}
	for _, txn := range applied.Transactions {
		txid := txn.ID()
		s.txns[txid] = txn
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
		// filter out outputs that are in limbo
		if !o.LimboSince.Equal(notLimboTime) {
			outputs = append(outputs, o.UnspentOutput)
		}
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

// MarkSpent implements Store.
func (s *EphemeralStore) MarkSpent(id types.SiacoinOutputID, spent bool) {
	o, ok := s.outputs[id]
	if !ok {
		return
	}
	if spent {
		o.LimboSince = time.Now()
	} else {
		o.LimboSince = notLimboTime
	}
	s.outputs[id] = o
}

// LimboOutputs implements Store.
func (s *EphemeralStore) LimboOutputs() []LimboOutput {
	outputs := make([]LimboOutput, 0, len(s.outputs))
	for _, o := range s.outputs {
		// filter out outputs that are not in limbo
		if o.LimboSince.Equal(notLimboTime) {
			outputs = append(outputs, o)
		}
	}
	return outputs
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
		outputs:       make(map[types.SiacoinOutputID]LimboOutput),
		txns:          make(map[types.TransactionID]types.Transaction),
		txnsAddrIndex: make(map[types.UnlockHash][]types.TransactionID),
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
