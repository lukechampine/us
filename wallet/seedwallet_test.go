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
	subscriber    modules.ConsensusSetSubscriber
	dscos         map[types.BlockHeight][]modules.DelayedSiacoinOutputDiff
	filecontracts map[types.FileContractID]types.FileContract
	height        types.BlockHeight
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
	m.height++
}

func (m *mockCS) mineBlock(fees types.Currency, addr types.UnlockHash) {
	b := types.Block{
		Transactions: []types.Transaction{{
			MinerFees: []types.Currency{fees},
		}},
		MinerPayouts: []types.SiacoinOutput{
			{UnlockHash: addr},
		},
	}
	b.MinerPayouts[0].Value = b.CalculateSubsidy(0)
	cc := modules.ConsensusChange{
		AppliedBlocks: []types.Block{b},
		DelayedSiacoinOutputDiffs: []modules.DelayedSiacoinOutputDiff{{
			SiacoinOutput:  b.MinerPayouts[0],
			ID:             b.MinerPayoutID(0),
			MaturityHeight: types.MaturityDelay,
		}},
	}
	for _, dsco := range m.dscos[m.height] {
		cc.SiacoinOutputDiffs = append(cc.SiacoinOutputDiffs, modules.SiacoinOutputDiff{
			Direction:     modules.DiffApply,
			SiacoinOutput: dsco.SiacoinOutput,
			ID:            dsco.ID,
		})
	}
	fastrand.Read(cc.ID[:])
	m.subscriber.ProcessConsensusChange(cc)
	m.height++
	if m.dscos == nil {
		m.dscos = make(map[types.BlockHeight][]modules.DelayedSiacoinOutputDiff)
	}
	dsco := cc.DelayedSiacoinOutputDiffs[0]
	m.dscos[dsco.MaturityHeight] = append(m.dscos[dsco.MaturityHeight], dsco)
}

func (m *mockCS) formContract(payout types.Currency, addr types.UnlockHash) {
	b := types.Block{
		Transactions: []types.Transaction{{
			FileContracts: []types.FileContract{{
				Payout: payout,
				ValidProofOutputs: []types.SiacoinOutput{
					{UnlockHash: addr, Value: payout},
					{},
				},
				MissedProofOutputs: []types.SiacoinOutput{
					{UnlockHash: addr, Value: payout},
					{},
				},
			}},
		}},
	}
	cc := modules.ConsensusChange{
		AppliedBlocks: []types.Block{b},
		FileContractDiffs: []modules.FileContractDiff{{
			FileContract: b.Transactions[0].FileContracts[0],
			ID:           b.Transactions[0].FileContractID(0),
			Direction:    modules.DiffApply,
		}},
	}
	fastrand.Read(cc.ID[:])
	m.subscriber.ProcessConsensusChange(cc)
	m.height++
	if m.filecontracts == nil {
		m.filecontracts = make(map[types.FileContractID]types.FileContract)
	}
	m.filecontracts[b.Transactions[0].FileContractID(0)] = b.Transactions[0].FileContracts[0]
}

func (m *mockCS) reviseContract(id types.FileContractID) {
	fc := m.filecontracts[id]
	delta := fc.ValidProofOutputs[0].Value.Div64(2)
	fc.ValidProofOutputs[0].Value = fc.ValidProofOutputs[0].Value.Sub(delta)
	fc.ValidProofOutputs[1].Value = fc.ValidProofOutputs[1].Value.Add(delta)
	fc.MissedProofOutputs[0].Value = fc.MissedProofOutputs[0].Value.Sub(delta)
	fc.MissedProofOutputs[1].Value = fc.MissedProofOutputs[1].Value.Add(delta)
	fc.RevisionNumber++
	b := types.Block{
		Transactions: []types.Transaction{{
			FileContractRevisions: []types.FileContractRevision{{
				ParentID:              id,
				NewFileSize:           fc.FileSize,
				NewFileMerkleRoot:     fc.FileMerkleRoot,
				NewWindowStart:        fc.WindowStart,
				NewWindowEnd:          fc.WindowEnd,
				NewValidProofOutputs:  fc.ValidProofOutputs,
				NewMissedProofOutputs: fc.MissedProofOutputs,
				NewUnlockHash:         fc.UnlockHash,
				NewRevisionNumber:     fc.RevisionNumber,
			}},
		}},
	}
	cc := modules.ConsensusChange{
		AppliedBlocks: []types.Block{b},
		FileContractDiffs: []modules.FileContractDiff{
			{
				FileContract: m.filecontracts[id],
				ID:           id,
				Direction:    modules.DiffRevert,
			},
			{
				FileContract: fc,
				ID:           id,
				Direction:    modules.DiffApply,
			},
		},
	}
	fastrand.Read(cc.ID[:])
	m.subscriber.ProcessConsensusChange(cc)
	m.height++
	m.filecontracts[id] = fc
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
	// randomly use either the on-disk DB store or the in-memory ephemeral store
	var store SeedStore
	if fastrand.Intn(2) == 0 {
		store = NewEphemeralSeedStore()
	} else {
		dir, err := ioutil.TempDir("", t.Name())
		if err != nil {
			t.Fatal(err)
		}
		store, err = NewBoltDBStore(filepath.Join(dir, "wallet.db"), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer store.(*BoltDBStore).Close()
		defer os.RemoveAll(dir)
	}

	sm := NewSeedManager(Seed{}, store.SeedIndex())
	w := NewSeedWallet(sm, store)
	cs := new(mockCS)
	cs.ConsensusSetSubscribe(w, store.ConsensusChangeID(), nil)

	// simulate genesis block
	cs.sendTxn(types.GenesisBlock.Transactions[0])

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
	if !w.Balance(false).Equals(types.SiacoinPrecision) {
		t.Fatal("balance should be 1 SC, got", w.Balance(false).HumanString())
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
	// simulate broadcasting by putting the transaction in limbo
	w.AddToLimbo(txn)
	// set and retrieve a memo for the transaction
	w.SetMemo(txn.ID(), []byte("test txn"))
	if string(w.Memo(txn.ID())) != "test txn" {
		t.Fatal("wrong memo for transaction")
	}

	// with limbo transactions applied, we should only have one UTXO (the change
	// output created by the transaction)
	outputs := w.UnspentOutputs(true)
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
		t.Fatal("UnspentOutputs(true) should match UnspentOutputs(false) when limbo is empty")
	} else if len(w.UnspentOutputs(false)) != 2 {
		t.Fatal("should have two UTXOs")
	}

	// mine a block reward
	cs.mineBlock(types.SiacoinPrecision, addr)
	rewards := w.BlockRewards(-1)
	if len(rewards) != 1 {
		t.Fatal("should have one block reward")
	} else if rewards[0].Timelock != types.MaturityDelay {
		t.Fatalf("block reward's timelock should be %v, got %v", types.MaturityDelay, rewards[0].Timelock)
	}
	// reward should not be reported as an UTXO yet
	if len(w.ValuedInputs()) != 2 {
		t.Fatal("should have two UTXOs")
	}
	// mine until the reward matures
	for i := 0; i < int(types.MaturityDelay); i++ {
		cs.mineBlock(types.ZeroCurrency, types.UnlockHash{})
	}
	// reward should now be available as an UTXO
	if len(w.ValuedInputs()) != 3 {
		t.Fatal("should have three UTXOs")
	}

	// form a file contract
	cs.formContract(types.SiacoinPrecision, addr)
	fcs := w.FileContracts(-1)
	if len(fcs) != 1 {
		t.Fatal("should have one file contract")
	}
	if len(w.FileContractHistory(fcs[0].ID)) != 1 {
		t.Fatal("contract history should contain only initial contract")
	}
	// revise the contract
	cs.reviseContract(fcs[0].ID)
	if len(w.FileContractHistory(fcs[0].ID)) != 2 {
		t.Fatal("contract history should contain revision")
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
		func() { _ = w.Balance(true) },
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
