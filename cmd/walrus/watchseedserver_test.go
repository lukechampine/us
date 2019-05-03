package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/types"
	"gitlab.com/NebulousLabs/fastrand"
	"lukechampine.com/us/cmd/walrus/api"
	"lukechampine.com/us/wallet"
)

func TestWatchSeedServer(t *testing.T) {
	dir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	store, err := wallet.NewBoltDBStore(filepath.Join(dir, "wallet.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	defer os.RemoveAll(dir)

	w := wallet.NewWatchOnlyWallet(store)
	cs := new(mockCS)
	cs.ConsensusSetSubscribe(w, store.ConsensusChangeID(), nil)
	ss := NewWatchSeedServer(w, stubTpool{})

	// initial balance should be zero
	var balance types.Currency
	if err := httpGet(ss, "/balance", &balance); err != nil {
		t.Fatal(err)
	} else if !balance.IsZero() {
		t.Fatal("balance should be zero")
	}

	// shouldn't have any transactions yet
	var txnHistory api.ResponseTransactions
	if err := httpGet(ss, "/transactions", &txnHistory); err != nil {
		t.Fatal(err)
	} else if len(txnHistory) != 0 {
		t.Fatal("transaction history should be empty")
	}

	// shouldn't have any addresses yet
	var addresses api.ResponseAddresses
	if err := httpGet(ss, "/addresses", &addresses); err != nil {
		t.Fatal(err)
	} else if len(addresses) != 0 {
		t.Fatal("address list should be empty")
	}

	// create and add an address
	seed := wallet.NewSeed()
	addrInfo := api.RequestAddresses{
		UnlockConditions: wallet.StandardUnlockConditions(seed.PublicKey(0)),
		KeyIndex:         0,
	}
	var addr types.UnlockHash
	if err := httpPost(ss, "/addresses", addrInfo, &addr); err != nil {
		t.Fatal(err)
	}

	// should have an address now
	if err := httpGet(ss, "/addresses", &addresses); err != nil {
		t.Fatal(err)
	} else if len(addresses) != 1 || addresses[0] != addr {
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
	if err := httpGet(ss, "/balance", &balance); err != nil {
		t.Fatal(err)
	} else if balance.Cmp(types.SiacoinPrecision) != 0 {
		t.Fatal("balance should be 1 SC")
	}

	// transaction should appear in history
	if err := httpGet(ss, "/transactions?max=2&addr="+addr.String(), &txnHistory); err != nil {
		t.Fatal(err)
	} else if len(txnHistory) != 1 {
		t.Fatal("transaction should appear in history")
	}
	var rtid api.ResponseTransactionsID
	if err := httpGet(ss, "/transactions/"+txnHistory[0].String(), &rtid); err != nil {
		t.Fatal(err)
	}
	htx := rtid.Transaction
	if len(htx.SiacoinOutputs) != 2 {
		t.Fatal("transaction should have two outputs")
	}

	// create an unsigned transaction using available outputs
	var outputs api.ResponseUTXOs
	if err := httpGet(ss, "/utxos", &outputs); err != nil {
		t.Fatal(err)
	} else if len(outputs) != 2 {
		t.Fatal("should have two UTXOs")
	}

	inputs := make([]wallet.ValuedInput, len(outputs))
	for i, o := range outputs {
		inputs[i] = wallet.ValuedInput{
			SiacoinInput: types.SiacoinInput{
				ParentID:         o.ID,
				UnlockConditions: o.UnlockConditions,
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

	// sign and broadcast the transaction
	for _, sci := range txn.SiacoinInputs {
		txnSig := wallet.StandardTransactionSignature(crypto.Hash(sci.ParentID))
		wallet.AppendTransactionSignature(&txn, txnSig, seed.SecretKey(0))
	}
	if err := txn.StandaloneValid(types.ASICHardforkHeight + 1); err != nil {
		t.Fatal(err)
	} else if err := httpPost(ss, "/broadcast", []types.Transaction{txn}, nil); err != nil {
		t.Fatal(err)
	}

	// outputs should no longer be reported as spendable
	if err := httpGet(ss, "/utxos", &outputs); err != nil {
		t.Fatal(err)
	} else if len(outputs) != 0 {
		t.Fatal("should have zero UTXOs")
	}

	// instead, they should appear in limbo
	if err := httpGet(ss, "/limbo", &outputs); err != nil {
		t.Fatal(err)
	} else if len(outputs) != 2 {
		t.Fatal("should have two UTXOs in limbo, got", len(outputs))
	}

	// bring back an output from limbo
	if err := httpDelete(ss, "/limbo/"+outputs[0].ID.String()); err != nil {
		t.Fatal(err)
	}
	if err := httpGet(ss, "/utxos", &outputs); err != nil {
		t.Fatal(err)
	} else if len(outputs) != 1 {
		t.Fatal("should have one UTXO, got", len(outputs))
	}
	if err := httpGet(ss, "/limbo", &outputs); err != nil {
		t.Fatal(err)
	} else if len(outputs) != 1 {
		t.Fatal("should have one UTXO in limbo")
	}
}

func TestWatchServerThreadSafety(t *testing.T) {
	store := wallet.NewEphemeralWatchOnlyStore()
	w := wallet.NewWatchOnlyWallet(store)
	cs := new(mockCS)
	cs.ConsensusSetSubscribe(w, store.ConsensusChangeID(), nil)
	ss := NewWatchSeedServer(w, stubTpool{})

	randomAddr := func() (info wallet.SeedAddressInfo) {
		info.UnlockConditions = wallet.StandardUnlockConditions(wallet.NewSeed().PublicKey(0))
		return
	}
	addr := randomAddr().UnlockConditions.UnlockHash()
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
		func() { httpGet(ss, "/balance", new(api.ResponseBalance)) },
		func() { httpPost(ss, "/addresses", api.RequestAddresses(randomAddr()), new(types.UnlockHash)) },
		func() { httpDelete(ss, "/addresses/"+randomAddr().UnlockConditions.UnlockHash().String()) },
		func() { httpGet(ss, "/addresses", new(api.ResponseAddresses)) },
		func() { httpGet(ss, "/transactions?max=2&addr="+addr.String(), new(api.ResponseTransactions)) },
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
