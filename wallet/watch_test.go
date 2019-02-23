package wallet

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/encoding"
	"gitlab.com/NebulousLabs/Sia/types"
	"gitlab.com/NebulousLabs/fastrand"
)

func TestWatchOnlyWallet(t *testing.T) {
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

	w := NewWatchOnlyWallet(store)
	cs := new(mockCS)
	cs.ConsensusSetSubscribe(w, store.ConsensusChangeID(), nil)

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

	// create and add an address
	seed := NewSeed()
	addrInfo := SeedAddressInfo{
		UnlockConditions: StandardUnlockConditions(seed.PublicKey(0)),
		KeyIndex:         0,
	}
	addr := addrInfo.UnlockConditions.UnlockHash()
	w.AddAddress(addr, encoding.Marshal(addrInfo))

	// should have an address now
	addresses = w.Addresses()
	if len(addresses) != 1 || addresses[0] != addr {
		t.Fatal("bad address list", addresses)
	}

	// simulate a transaction
	cs.sendTxn(types.Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{UnlockHash: addr, Value: types.SiacoinPrecision.Div64(2)},
			{UnlockHash: addr, Value: types.SiacoinPrecision.Div64(2)},
		},
	})

	// get new balance
	if !w.Balance().Equals(types.SiacoinPrecision) {
		t.Fatal("balance should be 1 SC")
	}

	// transaction should appear in history
	txnHistory = w.TransactionsByAddress(addr, 2)
	if len(txnHistory) != 1 {
		t.Fatal("transaction should appear in history")
	}
	htx, ok := w.Transaction(txnHistory[0])
	if !ok {
		t.Fatal("transaction should exist")
	} else if len(htx.SiacoinOutputs) != 2 {
		t.Fatal("transaction should have two outputs")
	}

	// create an unsigned transaction using available outputs
	outputs := w.UnspentOutputs()
	if len(outputs) != 2 {
		t.Fatal("should have two UTXOs")
	}

	// fetch the unlock conditions we stored earlier
	var uc types.UnlockConditions
	if err := encoding.Unmarshal(w.AddressInfo(addr), &uc); err != nil {
		t.Fatal(err)
	}

	inputs := make([]ValuedInput, len(outputs))
	for i, o := range outputs {
		inputs[i] = ValuedInput{
			SiacoinInput: types.SiacoinInput{
				ParentID:         o.ID,
				UnlockConditions: uc,
			},
			Value: o.Value,
		}
	}
	amount := types.SiacoinPrecision.Div64(2)
	dest := types.UnlockHash{}
	fee := types.NewCurrency64(10)
	txn, ok := sendSiacoins(amount, dest, fee, inputs, addr)
	if !ok {
		t.Fatal("insufficient funds")
	}

	// sign the transaction
	for _, sci := range txn.SiacoinInputs {
		txnSig := StandardTransactionSignature(crypto.Hash(sci.ParentID))
		AppendTransactionSignature(&txn, txnSig, seed.SecretKey(0))
	}
	if err := txn.StandaloneValid(types.ASICHardforkHeight + 1); err != nil {
		t.Fatal(err)
	}
	// simulate broadcasting by marking the inputs as spent
	for _, o := range txn.SiacoinInputs {
		if w.OwnsAddress(o.UnlockConditions.UnlockHash()) {
			w.MarkSpent(o.ParentID, true)
		}
	}

	// outputs should no longer be reported as spendable
	outputs = w.UnspentOutputs()
	if len(outputs) != 0 {
		t.Fatal("should have zero UTXOs")
	}

	// instead, they should appear in limbo
	limbo := w.LimboOutputs()
	if len(limbo) != 2 {
		t.Fatal("should have two UTXOs in limbo")
	}

	// bring back an output from limbo
	w.MarkSpent(limbo[0].ID, false)
	outputs = w.UnspentOutputs()
	if len(outputs) != 1 {
		t.Fatal("should have one UTXO")
	}
	limbo = w.LimboOutputs()
	if len(limbo) != 1 {
		t.Fatal("should have one UTXO in limbo")
	}
}

func TestWatchOnlyWalletThreadSafety(t *testing.T) {
	store := NewEphemeralWatchOnlyStore()
	w := NewWatchOnlyWallet(store)
	cs := new(mockCS)
	cs.ConsensusSetSubscribe(w, store.ConsensusChangeID(), nil)

	randomAddr := func() (addr types.UnlockHash) {
		fastrand.Read(addr[:])
		return
	}
	addr := randomAddr()
	w.AddAddress(addr, nil)

	txn := types.Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{UnlockHash: addr, Value: types.SiacoinPrecision.Div64(2)},
		},
	}

	// create a bunch of goroutines that call routes and add transactions
	// concurrently
	funcs := []func(){
		func() { cs.sendTxn(txn) },
		func() { _ = w.Balance() },
		func() { w.AddAddress(randomAddr(), nil) },
		func() { w.RemoveAddress(randomAddr()) },
		func() { _ = w.Addresses() },
		func() { _ = w.Transactions(-1) },
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
