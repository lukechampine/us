package host_test

import (
	"crypto/ed25519"
	"testing"
	"time"

	"go.sia.tech/siad/modules"
	"go.sia.tech/siad/types"
	"lukechampine.com/us/internal/ghost"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renterhost"
)

type chanTpool struct {
	stubTpool
	ch chan []types.Transaction
}

func (ctp *chanTpool) AcceptTransactionSet(txns []types.Transaction) error {
	ctp.ch <- txns
	return nil
}

func (ctp *chanTpool) recvTxns() []types.Transaction {
	select {
	case txns := <-ctp.ch:
		return txns
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}

func TestChain(t *testing.T) {
	ctp := &chanTpool{ch: make(chan []types.Transaction, 1)}
	host := ghost.New(t, ghost.FreeSettings, stubWallet{}, ctp)

	// "mine" genesis block
	host.ProcessConsensusChange(modules.ConsensusChange{
		AppliedBlocks: []types.Block{types.GenesisBlock},
		ID:            modules.ConsensusChangeID{1},
	})

	// form a contract ending at height 10
	renter, err := proto.NewUnlockedSession(host.Settings.NetAddress, host.PublicKey, 0)
	if err != nil {
		t.Fatal(err)
	} else if _, err := renter.Settings(); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	rev, txns, err := renter.FormContract(stubWallet{}, stubTpool{}, key, types.ZeroCurrency, 0, 10)
	if err != nil {
		t.Fatal(err)
	}

	// ChainManager should have submitted the contract transaction
	if txns := ctp.recvTxns(); txns == nil || txns[len(txns)-1].FileContractID(0) != rev.ID() {
		t.Fatal("host did not submit contract transaction")
	}

	// add a sector
	var sector [renterhost.SectorSize]byte
	if err := renter.Lock(rev.ID(), key, 0); err != nil {
		t.Fatal(err)
	} else if _, err := renter.Append(&sector); err != nil {
		t.Fatal(err)
	} else if err := renter.Close(); err != nil {
		t.Fatal(err)
	}

	// mine a block without the contract transaction; ChainManager should try
	// to resubmit it
	host.ProcessConsensusChange(modules.ConsensusChange{
		AppliedBlocks: []types.Block{{}},
		ID:            modules.ConsensusChangeID{2},
	})
	if txns := ctp.recvTxns(); txns == nil || txns[len(txns)-1].FileContractID(0) != rev.ID() {
		t.Fatal("host did not resubmit contract transaction")
	}

	// mine a block with the contract transaction; ChainManager should be placated
	host.ProcessConsensusChange(modules.ConsensusChange{
		AppliedBlocks: []types.Block{{Transactions: txns}},
		ID:            modules.ConsensusChangeID{3},
	})
	if ctp.recvTxns() != nil {
		t.Fatal("host submitted unexpected transaction")
	}

	// mine 8 more blocks, bringing contract to finalization height;
	// ChainManager should submit finalization transaction
	host.ProcessConsensusChange(modules.ConsensusChange{
		AppliedBlocks: make([]types.Block, 8),
		ID:            modules.ConsensusChangeID{4},
	})
	txns = ctp.recvTxns()
	if txns == nil || txns[len(txns)-1].FileContractRevisions[0].ParentID != rev.ID() {
		t.Fatal("host did not submit finalization transaction")
	}

	// mine a block containing the finalization transaction; ChainManager should
	// submit proof transaction.
	host.ProcessConsensusChange(modules.ConsensusChange{
		AppliedBlocks: []types.Block{{Transactions: txns}},
		ID:            modules.ConsensusChangeID{5},
	})
	host.ProcessConsensusChange(modules.ConsensusChange{
		AppliedBlocks: []types.Block{{}},
		ID:            modules.ConsensusChangeID{6},
	})
	if txns := ctp.recvTxns(); txns == nil || txns[len(txns)-1].StorageProofs[0].ParentID != rev.ID() {
		t.Fatal("host did not submit proof transaction")
	}
}
