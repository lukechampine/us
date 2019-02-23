package wallet

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"gitlab.com/NebulousLabs/fastrand"
)

type mockCS struct {
	subscriber modules.ConsensusSetSubscriber
}

func (m *mockCS) ConsensusSetSubscribe(s modules.ConsensusSetSubscriber, ccid modules.ConsensusChangeID, cancel <-chan struct{}) error {
	m.subscriber = s
	return nil
}

func (m *mockCS) sendTxn(txn types.Transaction) {
	outputs := make([]modules.SiacoinOutputDiff, len(txn.SiacoinOutputs))
	for i := range outputs {
		outputs[i] = modules.SiacoinOutputDiff{
			Direction:     modules.DiffApply,
			SiacoinOutput: txn.SiacoinOutputs[i],
			ID:            txn.SiacoinOutputID(uint64(i)),
		}
	}
	cc := modules.ConsensusChange{
		AppliedBlocks: []types.Block{{
			Transactions: []types.Transaction{txn},
		}},
		SiacoinOutputDiffs: outputs,
	}
	fastrand.Read(cc.ID[:])
	m.subscriber.ProcessConsensusChange(cc)
}

// sendSiacoins creates an unsigned transaction that sends amount siacoins to
// dest, or false if the supplied inputs are not sufficient to fund such a
// transaction. The heuristic for selecting funding inputs is unspecified. The
// transaction returns excess siacoins to changeAddr.
func sendSiacoins(amount types.Currency, dest types.UnlockHash, feePerByte types.Currency, inputs []ValuedInput, changeAddr types.UnlockHash) (types.Transaction, bool) {
	inputs, fee, change, ok := FundTransaction(amount, feePerByte, inputs)
	if !ok {
		return types.Transaction{}, false
	}

	txn := types.Transaction{
		SiacoinInputs: make([]types.SiacoinInput, len(inputs)),
		SiacoinOutputs: []types.SiacoinOutput{
			{Value: amount, UnlockHash: dest},
		},
		MinerFees:             []types.Currency{fee},
		TransactionSignatures: make([]types.TransactionSignature, 0, len(inputs)),
	}
	for i := range txn.SiacoinInputs {
		txn.SiacoinInputs[i] = inputs[i].SiacoinInput
	}
	if !change.IsZero() {
		txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{
			Value:      change,
			UnlockHash: changeAddr,
		})
	}
	return txn, true
}

func TestSeedWallet(t *testing.T) {
	dir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewBoltDBStore(filepath.Join(dir, "wallet.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	defer os.RemoveAll(dir)

	sm := NewSeedManager(Seed{}, store.SeedIndex())
	w := NewSeedWallet(sm, store)
	cs := new(mockCS)
	cs.ConsensusSetSubscribe(w, store.ConsensusChangeID(), nil)

	// simulate genesis block
	cs.sendTxn(types.GenesisBlock.Transactions[0])

	// initial balance should be zero
	if !w.Balance().IsZero() {
		t.Fatal("balance should be zero")
	}

	// shouldn't have any transactions yet
	txnHistory := w.Transactions(-1)
	if len(txnHistory) != 0 {
		t.Fatal("transaction history should be empty")
	}

	// shouldn't have any addresses yet
	addresses := w.Addresses()
	if len(addresses) != 0 {
		t.Fatal("address list should be empty")
	}

	// get an address
	addr := w.NextAddress()

	// seed index should be incremented to 1
	seedIndex := w.SeedIndex()
	if seedIndex != 1 {
		t.Fatal("seed index should be 1")
	}

	// should have an address now
	addresses = w.Addresses()
	if len(addresses) != 1 || addresses[0] != addr {
		t.Fatal("bad address list", addresses)
	}

	// address info should be present
	addrInfo, ok := w.AddressInfo(addr)
	if !ok || addrInfo.KeyIndex != 0 || addrInfo.UnlockConditions.UnlockHash() != addr {
		t.Fatal("address info is inaccurate")
	}

	oldCCID := w.ConsensusChangeID()
	oldHeight := w.ChainHeight()

	// simulate a transaction
	cs.sendTxn(types.Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{UnlockHash: addr, Value: types.SiacoinPrecision.Div64(2)},
			{UnlockHash: addr, Value: types.SiacoinPrecision.Div64(2)},
		},
	})

	// CCID should have changed
	if w.ConsensusChangeID() == oldCCID {
		t.Fatal("ConsensusChangeID did not change")
	} else if w.ChainHeight() != oldHeight+1 {
		t.Fatal("block height did not increment")
	}

	// get new balance
	if !w.Balance().Equals(types.SiacoinPrecision) {
		t.Fatal("balance should be 1 SC, got", w.Balance().HumanString())
	}

	// transaction should appear in history
	txnHistory = w.TransactionsByAddress(addr, 2)
	if len(txnHistory) != 1 {
		t.Fatal("transaction should appear in history")
	}
	htx, ok := w.Transaction(txnHistory[0])
	if !ok {
		t.Fatal("transaction should be present")
	} else if len(htx.SiacoinOutputs) != 2 {
		t.Fatal("transaction should have two outputs")
	}

	// create an unsigned transaction using available outputs
	inputs := w.ValuedInputs()
	if len(inputs) != 2 {
		t.Fatal("should have two UTXOs")
	}
	amount := types.SiacoinPrecision.Div64(2)
	dest := types.UnlockHash{}
	fee := types.NewCurrency64(10)
	txn, ok := sendSiacoins(amount, dest, fee, inputs, addr)
	if !ok {
		t.Fatal("insufficient funds")
	}

	// sign the transaction
	if err := w.SignTransaction(&txn, nil); err != nil {
		t.Fatal(err)
	} else if err := txn.StandaloneValid(types.ASICHardforkHeight + 1); err != nil {
		t.Fatal(err)
	}
	// simulate broadcasting by marking the outputs as spent
	for _, o := range txn.SiacoinInputs {
		if w.OwnsAddress(o.UnlockConditions.UnlockHash()) {
			w.MarkSpent(o.ParentID, true)
		}
	}
	// set and retrieve a memo for the transaction
	w.SetMemo(txn.ID(), []byte("test txn"))
	if string(w.Memo(txn.ID())) != "test txn" {
		t.Fatal("wrong memo for transaction")
	}

	// outputs should no longer be reported as spendable
	inputs = w.ValuedInputs()
	if len(inputs) != 0 {
		t.Fatal("should have zero UTXOs")
	}

	// instead, they should appear in limbo
	limbo := w.LimboOutputs()
	if len(limbo) != 2 {
		t.Fatal("should have two UTXOs in limbo")
	}

	// bring back an output from limbo
	w.MarkSpent(limbo[0].ID, false)
	inputs = w.ValuedInputs()
	if len(inputs) != 1 {
		t.Fatal("should have one UTXO")
	}
	limbo = w.LimboOutputs()
	if len(limbo) != 1 {
		t.Fatal("should have one UTXO in limbo")
	}
}

func TestSeedWalletThreadSafety(t *testing.T) {
	store := NewEphemeralSeedStore()
	sm := NewSeedManager(Seed{}, store.SeedIndex())
	w := NewSeedWallet(sm, store)
	cs := new(mockCS)
	cs.ConsensusSetSubscribe(w, store.ConsensusChangeID(), nil)

	addr := w.NextAddress()
	txn := types.Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{UnlockHash: addr, Value: types.SiacoinPrecision.Div64(2)},
		},
	}

	// create a bunch of goroutines that call methods and add transactions
	// concurrently
	funcs := []func(){
		func() { cs.sendTxn(txn) },
		func() { _ = w.Balance() },
		func() { _ = w.NextAddress() },
		func() { _ = w.Addresses() },
		func() { _ = w.TransactionsByAddress(addr, -1) },
	}
	var wg sync.WaitGroup
	wg.Add(len(funcs))
	for _, fn := range funcs {
		go func(fn func()) {
			for i := 0; i < 10; i++ {
				time.Sleep(time.Duration(fastrand.Intn(10)) * time.Millisecond)
				fn()
			}
			wg.Done()
		}(fn)
	}
	wg.Wait()
}
