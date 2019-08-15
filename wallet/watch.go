package wallet

import (
	"sync"

	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
)

// A WatchOnlyWallet is an unprivileged wallet that can track spendable outputs,
// but cannot sign transactions. It is safe for concurrent use.
type WatchOnlyWallet struct {
	store Store
	mu    sync.Mutex
}

// ConsensusSetSubscriber returns a modules.ConsensusSetSubscriber for w using
// the provided ChainStore.
func (w *WatchOnlyWallet) ConsensusSetSubscriber(store ChainStore) modules.ConsensusSetSubscriber {
	return lockedChainScanner{
		cs: ChainScanner{
			Owner: w.store,
			Store: store,
		},
		mu: &w.mu,
	}
}

// Balance returns the siacoin balance of the wallet. If the limbo flag is true,
// the balance reflects any transactions currently in Limbo.
func (w *WatchOnlyWallet) Balance(limbo bool) types.Currency {
	return SumOutputs(w.UnspentOutputs(limbo))
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
func (w *WatchOnlyWallet) AddAddress(info SeedAddressInfo) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.store.AddAddress(info)
}

// AddressInfo returns the metadata associated with the specified address.
func (w *WatchOnlyWallet) AddressInfo(addr types.UnlockHash) (SeedAddressInfo, bool) {
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

// SeedIndex returns the lowest seed index whose associated address is not
// tracked by the wallet; in other words, the index that should be used to
// generate a new address.
func (w *WatchOnlyWallet) SeedIndex() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.SeedIndex()
}

// UnspentOutputs returns the spendable outputs tracked by the wallet. If the
// limbo flag is true, the outputs reflect any transactions currently in Limbo.
func (w *WatchOnlyWallet) UnspentOutputs(limbo bool) []UnspentOutput {
	w.mu.Lock()
	defer w.mu.Unlock()
	outputs := w.store.UnspentOutputs()
	if limbo {
		outputs = CalculateLimboOutputs(w.store, w.store.LimboTransactions(), outputs)
	}
	return outputs
}

// AddToLimbo stores a transaction in Limbo. If the transaction is already in
// Limbo, its LimboSince timestamp is not updated.
func (w *WatchOnlyWallet) AddToLimbo(txn types.Transaction) {
	w.mu.Lock()
	w.store.AddToLimbo(txn)
	w.mu.Unlock()
}

// RemoveFromLimbo removes a transaction from Limbo.
func (w *WatchOnlyWallet) RemoveFromLimbo(txid types.TransactionID) {
	w.mu.Lock()
	w.store.RemoveFromLimbo(txid)
	w.mu.Unlock()
}

// LimboTransactions returns the transactions that have been broadcast, but have
// not appeared in the blockchain.
func (w *WatchOnlyWallet) LimboTransactions() []LimboTransaction {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.LimboTransactions()
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

// BlockRewards returns the block rewards tracked by the wallet.
func (w *WatchOnlyWallet) BlockRewards(n int) []BlockReward {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.BlockRewards(n)
}

// FileContracts returns the file contracts tracked by the wallet.
func (w *WatchOnlyWallet) FileContracts(n int) []FileContract {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.FileContracts(n)
}

// FileContractHistory returns the set of revisions made to the specified
// contract.
func (w *WatchOnlyWallet) FileContractHistory(id types.FileContractID) []FileContract {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.FileContractHistory(id)
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
func NewWatchOnlyWallet(store Store) *WatchOnlyWallet {
	return &WatchOnlyWallet{
		store: store,
	}
}
