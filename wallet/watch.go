package wallet

import (
	"sync"

	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
)

// A WatchOnlyWallet is an unprivileged wallet that can track spendable outputs,
// but cannot sign transactions. It is safe for concurrent use.
type WatchOnlyWallet struct {
	cs    ChainScanner
	store WatchOnlyStore
	mu    sync.Mutex
}

// ProcessConsensusChange implements modules.ConsensusSetSubscriber.
func (w *WatchOnlyWallet) ProcessConsensusChange(cc modules.ConsensusChange) {
	w.mu.Lock()
	w.cs.ProcessConsensusChange(cc)
	w.mu.Unlock()
}

// Balance returns the siacoin balance of the wallet. Unconfirmed transactions
// are not reflected in the balance.
func (w *WatchOnlyWallet) Balance() types.Currency {
	w.mu.Lock()
	defer w.mu.Unlock()
	return SumOutputs(w.store.UnspentOutputs())
}

// ConsensusChangeID returns the ConsensusChangeID most recently processed by
// the wallet.
func (w *WatchOnlyWallet) ConsensusChangeID() modules.ConsensusChangeID {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.ConsensusChangeID()
}

// ChainHeight returns the number of blocks processed by the wallet.
func (w *WatchOnlyWallet) ChainHeight() types.BlockHeight {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.ChainHeight()
}

// MarkSpent marks an output as spent or unspent.
func (w *WatchOnlyWallet) MarkSpent(id types.SiacoinOutputID, spent bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.store.MarkSpent(id, spent)
}

// OwnsAddress reports whether addr is being tracked by the wallet.
func (w *WatchOnlyWallet) OwnsAddress(addr types.UnlockHash) bool {
	w.mu.Lock()
	owned := w.store.OwnsAddress(addr)
	w.mu.Unlock()
	return owned
}

// Addresses returns the set of addresses tracked by the wallet.
func (w *WatchOnlyWallet) Addresses() []types.UnlockHash {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.Addresses()
}

// AddAddress adds an address to the wallet.
func (w *WatchOnlyWallet) AddAddress(addr types.UnlockHash, info []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.store.AddAddress(addr, info)
}

// AddressInfo returns the metadata associated with the specified address.
func (w *WatchOnlyWallet) AddressInfo(addr types.UnlockHash) (info []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.AddressInfo(addr)
}

// RemoveAddress removes an address from the wallet.
func (w *WatchOnlyWallet) RemoveAddress(addr types.UnlockHash) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.store.RemoveAddress(addr)
}

// UnspentOutputs returns the spendable outputs tracked by the wallet.
func (w *WatchOnlyWallet) UnspentOutputs() []UnspentOutput {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.UnspentOutputs()
}

// LimboOutputs returns the outputs that have been marked as spent, but have
// not been confirmed spent in the blockchain.
func (w *WatchOnlyWallet) LimboOutputs() []LimboOutput {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.LimboOutputs()
}

// SetMemo sets the memo associated with the specified transaction.
func (w *WatchOnlyWallet) SetMemo(txid types.TransactionID, memo []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.store.SetMemo(txid, memo)
}

// Memo returns the memo associated with the specified transaction.
func (w *WatchOnlyWallet) Memo(txid types.TransactionID) []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.Memo(txid)
}

// Transactions returns the IDs of the n most recent transactions in the
// blockchain that are relevant to the wallet, or fewer if less than n such
// transactions exist. If n < 0, all such transactions are returned. The IDs are
// ordered from oldest to newest.
func (w *WatchOnlyWallet) Transactions(n int) []types.TransactionID {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.Transactions(n)
}

// TransactionsByAddress returns the IDs of the n most recent transactions in
// the blockchain that are relevant to the specified wallet-owned address, or
// fewer if less than n such transactions exist. If n < 0, all such transactions
// are returned. The IDs are ordered from oldest to newest.
func (w *WatchOnlyWallet) TransactionsByAddress(addr types.UnlockHash, n int) []types.TransactionID {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.TransactionsByAddress(addr, n)
}

// Transaction returns the transaction with the specified id. The transaction
// must be relevant to the wallet.
func (w *WatchOnlyWallet) Transaction(id types.TransactionID) (types.Transaction, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.Transaction(id)
}

// NewWatchOnlyWallet intializes a WatchOnlyWallet using the provided store.
func NewWatchOnlyWallet(store WatchOnlyStore) *WatchOnlyWallet {
	return &WatchOnlyWallet{
		store: store,
		cs: ChainScanner{
			Owner: store,
			Store: store,
		},
	}
}
