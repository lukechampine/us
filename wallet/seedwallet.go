package wallet

import (
	"errors"
	"reflect"
	"sync"

	"go.sia.tech/siad/crypto"
	"go.sia.tech/siad/modules"
	"go.sia.tech/siad/types"
	"lukechampine.com/frand"
	"lukechampine.com/us/ed25519hash"
)

// A SeedWallet tracks outputs and transactions relevant to a set of
// seed-derived addresses. It does not control the seed itself (or any private
// keys), and therefore cannot sign transactions.
type SeedWallet struct {
	store Store
	mu    sync.Mutex
}

type seedWalletSubscriber struct {
	*SeedWallet
	cs ChainStore
}

func (s seedWalletSubscriber) ProcessConsensusChange(cc modules.ConsensusChange) {
	s.mu.Lock()
	s.cs.ApplyConsensusChange(FilterConsensusChange(cc, s.store, s.store.ChainHeight()))
	s.mu.Unlock()
}

// ConsensusSetSubscriber returns a modules.ConsensusSetSubscriber for w using
// the provided ChainStore.
func (w *SeedWallet) ConsensusSetSubscriber(store ChainStore) modules.ConsensusSetSubscriber {
	return seedWalletSubscriber{
		SeedWallet: w,
		cs:         store,
	}
}

// Balance returns the siacoin balance of the wallet. If the limbo flag is true,
// the balance reflects any transactions currently in Limbo.
func (w *SeedWallet) Balance(limbo bool) types.Currency {
	return SumOutputs(w.UnspentOutputs(limbo))
}

// ConsensusChangeID returns the ConsensusChangeID most recently processed by
// the wallet.
func (w *SeedWallet) ConsensusChangeID() modules.ConsensusChangeID {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.ConsensusChangeID()
}

// ChainHeight returns the number of blocks processed by the wallet.
func (w *SeedWallet) ChainHeight() types.BlockHeight {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.ChainHeight()
}

// OwnsAddress reports whether addr is being tracked by the wallet.
func (w *SeedWallet) OwnsAddress(addr types.UnlockHash) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.OwnsAddress(addr)
}

// Addresses returns the set of addresses tracked by the wallet.
func (w *SeedWallet) Addresses() []types.UnlockHash {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.Addresses()
}

// AddAddress adds an address to the wallet.
func (w *SeedWallet) AddAddress(info SeedAddressInfo) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.store.AddAddress(info)
}

// AddressInfo returns the metadata associated with the specified address.
func (w *SeedWallet) AddressInfo(addr types.UnlockHash) (SeedAddressInfo, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.AddressInfo(addr)
}

// RemoveAddress removes an address from the wallet.
func (w *SeedWallet) RemoveAddress(addr types.UnlockHash) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.store.RemoveAddress(addr)
}

// SeedIndex returns the lowest seed index whose associated address is not
// tracked by the wallet; in other words, the index that should be used to
// generate a new address.
func (w *SeedWallet) SeedIndex() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.SeedIndex()
}

// UnspentOutputs returns the spendable outputs tracked by the wallet. If the
// limbo flag is true, the outputs reflect any transactions currently in Limbo.
func (w *SeedWallet) UnspentOutputs(limbo bool) []UnspentOutput {
	w.mu.Lock()
	defer w.mu.Unlock()
	outputs := w.store.UnspentOutputs()
	if limbo {
		outputs = CalculateLimboOutputs(w.store, w.store.LimboTransactions(), outputs)
	}
	return outputs
}

// ValuedInputs returns the spendable outputs tracked by the wallet along with
// their UnlockConditions, for immediate use as inputs.
func (w *SeedWallet) ValuedInputs() []ValuedInput {
	w.mu.Lock()
	defer w.mu.Unlock()
	outputs := w.store.UnspentOutputs()
	inputs := make([]ValuedInput, len(outputs))
	for i, o := range outputs {
		info, ok := w.store.AddressInfo(o.UnlockHash)
		if !ok {
			panic("missing unlock conditions for " + o.UnlockHash.String())
		}
		inputs[i] = ValuedInput{
			SiacoinInput: types.SiacoinInput{
				ParentID:         o.ID,
				UnlockConditions: info.UnlockConditions,
			},
			Value: o.Value,
		}
	}
	return inputs
}

// AddToLimbo stores a transaction in Limbo. If the transaction is already in
// Limbo, its LimboSince timestamp is not updated.
func (w *SeedWallet) AddToLimbo(txn types.Transaction) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.store.AddToLimbo(txn)
}

// RemoveFromLimbo removes a transaction from Limbo.
func (w *SeedWallet) RemoveFromLimbo(txid types.TransactionID) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.store.RemoveFromLimbo(txid)
}

// LimboTransactions returns the transactions that have been broadcast, but have
// not appeared in the blockchain.
func (w *SeedWallet) LimboTransactions() []LimboTransaction {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.LimboTransactions()
}

// SetMemo sets the memo associated with the specified transaction.
func (w *SeedWallet) SetMemo(txid types.TransactionID, memo []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.store.SetMemo(txid, memo)
}

// Memo returns the memo associated with the specified transaction.
func (w *SeedWallet) Memo(txid types.TransactionID) []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.Memo(txid)
}

// BlockRewards returns the block rewards tracked by the wallet.
func (w *SeedWallet) BlockRewards(n int) []BlockReward {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.BlockRewards(n)
}

// FileContracts returns the file contracts tracked by the wallet.
func (w *SeedWallet) FileContracts(n int) []FileContract {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.FileContracts(n)
}

// FileContractHistory returns the set of revisions made to the specified
// contract.
func (w *SeedWallet) FileContractHistory(id types.FileContractID) []FileContract {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.FileContractHistory(id)
}

// Transactions returns the IDs of the n most recent transactions in the
// blockchain that are relevant to the wallet, or fewer if less than n such
// transactions exist. If n < 0, all such transactions are returned. The IDs are
// ordered from oldest to newest.
func (w *SeedWallet) Transactions(n int) []types.TransactionID {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.Transactions(n)
}

// TransactionsByAddress returns the IDs of the n most recent transactions in
// the blockchain that are relevant to the specified wallet-owned address, or
// fewer if less than n such transactions exist. If n < 0, all such transactions
// are returned. The IDs are ordered from oldest to newest.
func (w *SeedWallet) TransactionsByAddress(addr types.UnlockHash, n int) []types.TransactionID {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.TransactionsByAddress(addr, n)
}

// Transaction returns the transaction with the specified id. The transaction
// must be relevant to the wallet.
func (w *SeedWallet) Transaction(id types.TransactionID) (Transaction, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.store.Transaction(id)
}

// New intializes a SeedWallet using the provided store.
func New(store Store) *SeedWallet {
	return &SeedWallet{
		store: store,
	}
}

// A HotWallet pairs a SeedWallet with a Seed, providing a more convenient API
// for generating addresses and signing transactions.
type HotWallet struct {
	*SeedWallet
	seed Seed
	used map[types.SiacoinOutputID]struct{}
	mu   sync.Mutex
}

// Address returns a new (unused) address derived from the wallet's seed.
func (w *HotWallet) Address() (types.UnlockHash, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	index := w.SeedIndex()
	info := SeedAddressInfo{
		UnlockConditions: StandardUnlockConditions(w.seed.PublicKey(index)),
		KeyIndex:         index,
	}
	w.AddAddress(info)
	return info.UnlockHash(), nil
}

// FundTransaction adds inputs to txn worth at least amount, adding a change
// output if needed. It returns the added input IDs, for use with
// SignTransaction. It also returns a function that will "unclaim" the inputs;
// this function must be called once the transaction has been broadcast or
// discarded.
func (w *HotWallet) FundTransaction(txn *types.Transaction, amount types.Currency) ([]crypto.Hash, func(), error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if amount.IsZero() {
		return nil, func() {}, nil
	}
	// UnspentOutputs(true) returns the outputs that exist after Limbo
	// transactions are applied. This is not ideal, because the transactions
	// might never be confirmed. On the other hand, UnspentOutputs(false) won't
	// return any outputs that were created in Limbo transactions, but it *will*
	// return outputs that have been *spent* in Limbo transactions. So what we
	// really want is the intersection of these sets, keeping only the confirmed
	// outputs that were not spent in Limbo transactions. We also filter out any
	// outputs in the 'used' set, i.e. outputs that are have been claimed by
	// another FundTransaction call (but have not yet been broadcast).
	limboOutputs := w.UnspentOutputs(true)
	unused := limboOutputs[:0]
	for _, lo := range limboOutputs {
		if _, ok := w.used[lo.ID]; !ok {
			unused = append(unused, lo)
		}
	}
	limboOutputs = unused
	confirmedOutputs := w.UnspentOutputs(false)
	unused = confirmedOutputs[:0]
	for _, co := range confirmedOutputs {
		if _, ok := w.used[co.ID]; !ok {
			unused = append(unused, co)
		}
	}
	confirmedOutputs = unused
	var fundingOutputs []UnspentOutput
	for _, lo := range limboOutputs {
		for _, co := range confirmedOutputs {
			if co.ID == lo.ID {
				fundingOutputs = append(fundingOutputs, lo)
				break
			}
		}
	}
	var balance types.Currency
	for _, o := range fundingOutputs {
		balance = balance.Add(o.Value)
	}
	var limboBalance types.Currency
	for _, o := range limboOutputs {
		limboBalance = limboBalance.Add(o.Value)
	}
	if balance.Cmp(amount) < 0 {
		if limboBalance.Cmp(amount) < 0 {
			return nil, nil, ErrInsufficientFunds
		}
		// confirmed outputs are not sufficient, but limbo outputs are
		fundingOutputs = limboOutputs
	}
	// choose outputs randomly
	frand.Shuffle(len(fundingOutputs), reflect.Swapper(fundingOutputs))

	// keep adding outputs until we have enough
	var outputSum types.Currency
	for i, o := range fundingOutputs {
		if outputSum = outputSum.Add(o.Value); outputSum.Cmp(amount) >= 0 {
			fundingOutputs = fundingOutputs[:i+1]
			break
		}
	}

	var toSign []crypto.Hash
	for _, o := range fundingOutputs {
		info, ok := w.AddressInfo(o.UnlockHash)
		if !ok {
			return nil, nil, errors.New("missing unlock conditions for address")
		}
		txn.SiacoinInputs = append(txn.SiacoinInputs, types.SiacoinInput{
			ParentID:         o.ID,
			UnlockConditions: info.UnlockConditions,
		})
		txn.TransactionSignatures = append(txn.TransactionSignatures, StandardTransactionSignature(crypto.Hash(o.ID)))
		toSign = append(toSign, crypto.Hash(o.ID))
	}
	// add change output, if needed
	if change := outputSum.Sub(amount); !change.IsZero() {
		index := w.SeedIndex()
		info := SeedAddressInfo{
			UnlockConditions: StandardUnlockConditions(w.seed.PublicKey(index)),
			KeyIndex:         index,
		}
		w.AddAddress(info)
		txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{
			UnlockHash: info.UnlockHash(),
			Value:      change,
		})
	}

	for _, o := range fundingOutputs {
		w.used[o.ID] = struct{}{}
	}
	discard := func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		for _, o := range fundingOutputs {
			delete(w.used, o.ID)
		}
	}
	return toSign, discard, nil
}

// SignTransaction signs the specified transaction using keys derived from the
// wallet seed. If toSign is nil, SignTransaction will automatically add
// TransactionSignatures for each input owned by the seed. If toSign is not nil,
// it a list of indices of TransactionSignatures already present in txn;
// SignTransaction will fill in the Signature field of each.
func (w *HotWallet) SignTransaction(txn *types.Transaction, toSign []crypto.Hash) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(toSign) == 0 {
		// lazy mode: add standard sigs for every input we own
		for _, input := range txn.SiacoinInputs {
			info, ok := w.AddressInfo(input.UnlockConditions.UnlockHash())
			if !ok {
				continue
			}
			sk := w.seed.SecretKey(info.KeyIndex)
			txnSig := StandardTransactionSignature(crypto.Hash(input.ParentID))
			AppendTransactionSignature(txn, txnSig, sk)
		}
		return nil
	}

	sigAddr := func(id crypto.Hash) (types.UnlockHash, bool) {
		for _, sci := range txn.SiacoinInputs {
			if crypto.Hash(sci.ParentID) == id {
				return sci.UnlockConditions.UnlockHash(), true
			}
		}
		for _, sfi := range txn.SiafundInputs {
			if crypto.Hash(sfi.ParentID) == id {
				return sfi.UnlockConditions.UnlockHash(), true
			}
		}
		for _, fcr := range txn.FileContractRevisions {
			if crypto.Hash(fcr.ParentID) == id {
				return fcr.UnlockConditions.UnlockHash(), true
			}
		}
		return types.UnlockHash{}, false
	}
	sign := func(i int) error {
		addr, ok := sigAddr(txn.TransactionSignatures[i].ParentID)
		if !ok {
			return errors.New("invalid id")
		}
		info, ok := w.AddressInfo(addr)
		if !ok {
			return errors.New("can't sign")
		}
		sk := w.seed.SecretKey(info.KeyIndex)
		txn.TransactionSignatures[i].Signature = ed25519hash.Sign(sk, txn.SigHash(i, types.FoundationHardforkHeight+1))
		return nil
	}

outer:
	for _, parent := range toSign {
		for sigIndex, sig := range txn.TransactionSignatures {
			if sig.ParentID == parent {
				if err := sign(sigIndex); err != nil {
					return err
				}
				continue outer
			}
		}
		return errors.New("sighash not found in transaction")
	}
	return nil
}

// NewHotWallet intializes a HotWallet using the provided wallet and seed.
func NewHotWallet(sw *SeedWallet, seed Seed) *HotWallet {
	return &HotWallet{
		SeedWallet: sw,
		seed:       seed,
	}
}
