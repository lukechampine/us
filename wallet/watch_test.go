package wallet

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/frand"
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
	cs.ConsensusSetSubscribe(w.ConsensusSetSubscriber(store), store.ConsensusChangeID(), nil)

	// initial balance should be zero
	if !w.Balance(false).IsZero() {
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
	w.AddAddress(addrInfo)

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
	if !w.Balance(false).Equals(types.SiacoinPrecision) {
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
	outputs := w.UnspentOutputs(true)
	if len(outputs) != 2 {
		t.Fatal("should have two UTXOs")
	}

	// fetch the unlock conditions we stored earlier
	info, ok := w.AddressInfo(addr)
	if !ok {
		t.Fatal("missing address info")
	}
	uc := info.UnlockConditions

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

	// simulate broadcasting by putting the transaction in limbo
	w.AddToLimbo(txn)
	// set and retrieve a memo for the transaction
	w.SetMemo(txn.ID(), []byte("test txn"))
	if string(w.Memo(txn.ID())) != "test txn" {
		t.Fatal("wrong memo for transaction")
	}

	// with limbo transactions applied, we should only have one UTXO (the change
	// output created by the transaction)
	outputs = w.UnspentOutputs(true)
	if len(outputs) != 1 {
		t.Fatal("should have one UTXO")
	} else if outputs[0].UnlockHash != addr {
		t.Fatal("UTXO should be sent to addr")
	}

	// the spent outputs should appear in the limbo transaction
	limbo := w.LimboTransactions()
	if len(limbo) != 1 {
		t.Fatal("should have one transaction in limbo")
	} else if len(limbo[0].SiacoinInputs) != 2 {
		t.Fatal("limbo transaction should have two inputs")
	}

	// bring the transaction back from limbo
	w.RemoveFromLimbo(limbo[0].ID())
	// we should have two UTXOs again
	if limbo := w.LimboTransactions(); len(limbo) != 0 {
		t.Fatal("limbo should be empty")
	} else if len(w.UnspentOutputs(true)) != len(w.UnspentOutputs(false)) {
		t.Fatal("w.UnspentOutputs(true) should match w.UnspentOutputs(false) when limbo is empty")
	} else if len(w.UnspentOutputs(false)) != 2 {
		t.Fatal("should have two UTXOs")
	}
}

func TestWatchOnlyWalletThreadSafety(t *testing.T) {
	store := NewEphemeralWatchOnlyStore()
	w := NewWatchOnlyWallet(store)
	cs := new(mockCS)
	cs.ConsensusSetSubscribe(w.ConsensusSetSubscriber(store), store.ConsensusChangeID(), nil)

	seed := NewSeed()
	randomAddrInfo := func() SeedAddressInfo {
		index := frand.Uint64n(10)
		return SeedAddressInfo{
			UnlockConditions: StandardUnlockConditions(seed.PublicKey(index)),
			KeyIndex:         index,
		}
	}
	info := randomAddrInfo()
	w.AddAddress(info)

	txn := types.Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{UnlockHash: CalculateUnlockHash(info.UnlockConditions), Value: types.SiacoinPrecision.Div64(2)},
		},
	}

	// create a bunch of goroutines that call routes and add transactions
	// concurrently
	funcs := []func(){
		func() { cs.sendTxn(txn) },
		func() { _ = w.Balance(true) },
		func() { w.AddAddress(randomAddrInfo()) },
		func() { w.RemoveAddress(CalculateUnlockHash(randomAddrInfo().UnlockConditions)) },
		func() { _ = w.Addresses() },
		func() { _ = w.Transactions(-1) },
	}
	var wg sync.WaitGroup
	wg.Add(len(funcs))
	for _, fn := range funcs {
		go func(fn func()) {
			for i := 0; i < 10; i++ {
				time.Sleep(time.Duration(frand.Intn(10)) * time.Millisecond)
				fn()
			}
			wg.Done()
		}(fn)
	}
	wg.Wait()
}
