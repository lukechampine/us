package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"gitlab.com/NebulousLabs/fastrand"
	"lukechampine.com/us/cmd/walrus/api"
	"lukechampine.com/us/wallet"
)

type stubTpool struct{}

func (stubTpool) AcceptTransactionSet([]types.Transaction) (err error)   { return }
func (stubTpool) FeeEstimation() (min, max types.Currency)               { return }
func (stubTpool) TransactionSet(id crypto.Hash) (ts []types.Transaction) { return }

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
func sendSiacoins(amount types.Currency, dest types.UnlockHash, feePerByte types.Currency, inputs []wallet.ValuedInput, changeAddr types.UnlockHash) (types.Transaction, bool) {
	inputs, fee, change, ok := wallet.FundTransaction(amount, feePerByte, inputs)
	if !ok {
		return types.Transaction{}, false
	}

	txn := types.Transaction{
		SiacoinInputs: make([]types.SiacoinInput, len(inputs)),
		SiacoinOutputs: []types.SiacoinOutput{
			{Value: amount, UnlockHash: dest},
			{},
		}[:1], // prevent extra allocation for change output
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

func httpGet(h http.Handler, route string, resp interface{}) error {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", route, nil))
	r := rec.Result()
	if r.StatusCode != 200 {
		err, _ := ioutil.ReadAll(r.Body)
		return errors.New(string(err))
	}
	return json.NewDecoder(r.Body).Decode(resp)
}

func httpPost(h http.Handler, route string, data, resp interface{}) error {
	var body io.Reader
	if data != nil {
		js, _ := json.Marshal(data)
		body = bytes.NewReader(js)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", route, body))
	r := rec.Result()
	if r.StatusCode != 200 {
		err, _ := ioutil.ReadAll(r.Body)
		return errors.New(string(err))
	}
	if resp == nil {
		return nil
	}
	return json.NewDecoder(r.Body).Decode(resp)
}

func httpPut(h http.Handler, route string, data interface{}) error {
	var body io.Reader
	if data != nil {
		js, _ := json.Marshal(data)
		body = bytes.NewReader(js)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("PUT", route, body))
	r := rec.Result()
	if r.StatusCode != 200 {
		err, _ := ioutil.ReadAll(r.Body)
		return errors.New(string(err))
	}
	return nil
}

func httpDelete(h http.Handler, route string) error {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("DELETE", route, nil))
	r := rec.Result()
	if r.StatusCode != 200 {
		err, _ := ioutil.ReadAll(r.Body)
		return errors.New(string(err))
	}
	return nil
}

func TestSeedServer(t *testing.T) {
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

	sm := wallet.NewSeedManager(wallet.Seed{}, store.SeedIndex())
	w := wallet.NewSeedWallet(sm, store)
	cs := new(mockCS)
	cs.ConsensusSetSubscribe(w, store.ConsensusChangeID(), nil)
	ss := NewSeedServer(w, stubTpool{})

	// simulate genesis block
	cs.sendTxn(types.GenesisBlock.Transactions[0])

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

	// get an address
	var addr types.UnlockHash
	if err := httpPost(ss, "/nextaddress", nil, &addr); err != nil {
		t.Fatal(err)
	}

	// seed index should be incremented to 1
	var seedIndex api.ResponseSeedIndex
	if err := httpGet(ss, "/seedindex", &seedIndex); err != nil {
		t.Fatal(err)
	} else if seedIndex != 1 {
		t.Fatal("seed index should be 1")
	}

	// should have an address now
	if err := httpGet(ss, "/addresses", &addresses); err != nil {
		t.Fatal(err)
	} else if len(addresses) != 1 || addresses[0] != addr {
		t.Fatal("bad address list", addresses)
	}

	// address info should be present
	var addrInfo api.ResponseAddressesAddr
	if err := httpGet(ss, "/addresses/"+addr.String(), &addrInfo); err != nil {
		t.Fatal(err)
	} else if addrInfo.KeyIndex != 0 || addrInfo.UnlockConditions.UnlockHash() != addr {
		t.Fatal("address info is inaccurate")
	}

	var oldConsensus api.ResponseConsensus
	if err := httpGet(ss, "/consensus", &oldConsensus); err != nil {
		t.Fatal(err)
	}

	// simulate a transaction
	cs.sendTxn(types.Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{UnlockHash: addr, Value: types.SiacoinPrecision.Div64(2)},
			{UnlockHash: addr, Value: types.SiacoinPrecision.Div64(2)},
		},
	})

	// CCID should have changed
	var newConsensus api.ResponseConsensus
	if err := httpGet(ss, "/consensus", &newConsensus); err != nil {
		t.Fatal(err)
	}
	if newConsensus.CCID == oldConsensus.CCID {
		t.Fatal("ConsensusChangeID did not change")
	} else if newConsensus.Height != oldConsensus.Height+1 {
		t.Fatal("block height did not increment")
	}

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
	var htx api.ResponseTransactionsID
	if err := httpGet(ss, "/transactions/"+txnHistory[0].String(), &htx); err != nil {
		t.Fatal(err)
	} else if len(htx.Transaction.SiacoinOutputs) != 2 {
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
	signReq := api.RequestSign{Transaction: txn}
	if err := httpPost(ss, "/sign", signReq, &txn); err != nil {
		t.Fatal(err)
	} else if err := txn.StandaloneValid(types.ASICHardforkHeight + 1); err != nil {
		t.Fatal(err)
	} else if err := httpPost(ss, "/broadcast", []types.Transaction{txn}, nil); err != nil {
		t.Fatal(err)
	}
	// set and retrieve a memo for the transaction
	memo := json.RawMessage(`"test txn"`)
	if err := httpPut(ss, "/memos/"+txn.ID().String(), memo); err != nil {
		t.Fatal(err)
	} else if err := httpGet(ss, "/memos/"+txn.ID().String(), &memo); err != nil {
		t.Fatal(err)
	} else if string(memo) != `"test txn"` {
		t.Fatal("wrong memo for transaction")
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
		t.Fatal("should have two UTXOs in limbo")
	}

	// bring back an output from limbo
	if err := httpDelete(ss, "/limbo/"+outputs[0].ID.String()); err != nil {
		t.Fatal(err)
	}
	if err := httpGet(ss, "/utxos", &outputs); err != nil {
		t.Fatal(err)
	} else if len(outputs) != 1 {
		t.Fatal("should have one UTXO")
	}
	if err := httpGet(ss, "/limbo", &outputs); err != nil {
		t.Fatal(err)
	} else if len(outputs) != 1 {
		t.Fatal("should have one UTXO in limbo")
	}
}

func TestSeedServerThreadSafety(t *testing.T) {
	store := wallet.NewEphemeralSeedStore()
	sm := wallet.NewSeedManager(wallet.Seed{}, store.SeedIndex())
	w := wallet.NewSeedWallet(sm, store)
	cs := new(mockCS)
	cs.ConsensusSetSubscribe(w, store.ConsensusChangeID(), nil)
	ss := NewSeedServer(w, stubTpool{})

	addr := sm.NextAddress()
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
		func() { httpPost(ss, "/nextaddress", nil, new(api.ResponseNextAddress)) },
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
