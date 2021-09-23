package host_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.sia.tech/siad/build"
	"go.sia.tech/siad/crypto"
	"go.sia.tech/siad/modules"
	"go.sia.tech/siad/modules/consensus"
	"go.sia.tech/siad/modules/gateway"
	"go.sia.tech/siad/modules/transactionpool"
	"go.sia.tech/siad/types"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/internal/ghost"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renterhost"
	"lukechampine.com/us/wallet"
)

type tpoolBridge struct {
	tp modules.TransactionPool
}

func (tpb tpoolBridge) AcceptTransactionSet(txnSet []types.Transaction) error {
	return tpb.tp.AcceptTransactionSet(txnSet)
}

func (tpb tpoolBridge) UnconfirmedParents(txn types.Transaction) ([]types.Transaction, error) {
	return nil, nil
}

func (tpb tpoolBridge) FeeEstimate() (min, max types.Currency, err error) {
	min, max = tpb.tp.FeeEstimation()
	return
}

type testNode struct {
	g      modules.Gateway
	cs     modules.ConsensusSet
	tp     modules.TransactionPool
	wallet *wallet.HotWallet
	tb     testing.TB
}

func (n *testNode) connect(m *testNode) {
	addr := modules.NetAddress(net.JoinHostPort("127.0.0.1", m.g.Address().Port()))
	if err := n.g.Connect(addr); err != nil && !strings.Contains(err.Error(), "already connected") {
		n.tb.Fatal(err, addr)
	}
}

func (n *testNode) mineBlock() {
	addr, _ := n.wallet.Address()
	b := types.Block{
		ParentID:  n.cs.CurrentBlock().ID(),
		Timestamp: types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{
			UnlockHash: addr,
		}},
		Transactions: n.tp.TransactionList(),
	}
	b.MinerPayouts[0].Value = b.CalculateSubsidy(n.height() + 1)
	target, _ := n.cs.ChildTarget(n.cs.CurrentBlock().ID())
	merkleRoot := b.MerkleRoot()
	header := make([]byte, 80)
	copy(header, b.ParentID[:])
	binary.LittleEndian.PutUint64(header[40:48], uint64(b.Timestamp))
	copy(header[48:], merkleRoot[:])
	for nonce := uint64(0); ; nonce += types.ASICHardforkFactor {
		binary.LittleEndian.PutUint64(header[32:40], nonce)
		id := crypto.HashBytes(header)
		if bytes.Compare(target[:], id[:]) >= 0 {
			copy(b.Nonce[:], header[32:40])
			if err := n.cs.AcceptBlock(b); err != nil {
				n.tb.Fatal(err)
			}
			return
		}
	}
}

func (n *testNode) mineBlocks(blocks types.BlockHeight) {
	for blocks > 0 {
		n.mineBlock()
		blocks--
	}
}

func (n *testNode) height() types.BlockHeight {
	return n.cs.Height()
}

func (n *testNode) balance() types.Currency {
	return n.wallet.Balance(false)
}

func (n *testNode) Close() error {
	n.tp.Close()
	n.cs.Close()
	n.g.Close()
	return nil
}

func newTestNode(tb testing.TB) *testNode {
	dir, err := ioutil.TempDir("", tb.Name())
	if err != nil {
		tb.Fatal(err)
	}
	os.RemoveAll(dir)
	tb.Cleanup(func() { os.RemoveAll(dir) })
	g, err := gateway.New(":0", false, filepath.Join(dir, "gateway"))
	if err != nil {
		tb.Fatal(err)
	}
	cs, errCh := consensus.New(g, false, filepath.Join(dir, "consensus"))
	go func() {
		if err := <-errCh; err != nil {
			panic(err)
		}
	}()
	tp, err := transactionpool.New(cs, g, filepath.Join(dir, "tpool"))
	if err != nil {
		tb.Fatal(err)
	}
	store := wallet.NewEphemeralStore()
	sw := wallet.New(store)
	if err := cs.ConsensusSetSubscribe(sw.ConsensusSetSubscriber(store), modules.ConsensusChangeBeginning, nil); err != nil {
		tb.Fatal(err)
	}
	w := wallet.NewHotWallet(sw, wallet.NewSeed())
	return &testNode{
		g:      g,
		cs:     cs,
		tp:     tp,
		wallet: w,
		tb:     tb,
	}
}

func TestIntegrationHost(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	} else if build.Release != "testing" {
		t.Skip("must be run with -tags=testing")
	}

	// create renter and host nodes, and connect them together
	renterNode := newTestNode(t)
	hostNode := newTestNode(t)
	renterNode.connect(hostNode)
	hostNode.connect(renterNode)

	// helper function that blocks until renterNode and hostNode have the same
	// chain tip
	synchronize := func() {
		time.Sleep(100 * time.Millisecond)
		for renterNode.cs.CurrentBlock().ID() != hostNode.cs.CurrentBlock().ID() {
			time.Sleep(10 * time.Millisecond)
		}
	}

	// fund both wallets
	hostNode.mineBlock()
	synchronize()
	renterNode.mineBlocks(types.MaturityDelay + 1)
	// make sure we're above the file contract hardfork height
	for renterNode.height() <= types.TaxHardforkHeight {
		renterNode.mineBlock()
	}
	synchronize()

	// initialize host
	host := ghost.New(t, ghost.DefaultSettings, hostNode.wallet, tpoolBridge{hostNode.tp})
	if err := hostNode.cs.ConsensusSetSubscribe(host, modules.ConsensusChangeBeginning, nil); err != nil {
		t.Fatal(err)
	}

	// form a contract ending in 10 blocks
	currrentHeight := renterNode.height()
	scannedHost := hostdb.ScannedHost{
		HostSettings: host.Settings,
		PublicKey:    host.PublicKey,
	}
	contractKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	rev, _, err := proto.FormContract(renterNode.wallet, tpoolBridge{renterNode.tp}, contractKey, scannedHost, types.SiacoinPrecision.Mul64(1e3), currrentHeight, currrentHeight+10)
	if err != nil {
		t.Fatal(err)
	}

	// host should have submitted the contract transaction
	if txns := hostNode.tp.TransactionList(); len(txns) != 1 || txns[len(txns)-1].FileContractID(0) != rev.ID() {
		t.Fatal("host did not submit contract transaction")
	}

	// mine a block with the contract transaction
	renterNode.mineBlock()
	synchronize()
	currrentHeight++

	// add 7 sectors to the contract
	sess, err := proto.NewSession(host.Settings.NetAddress, host.PublicKey, rev.ID(), contractKey, currrentHeight)
	if err != nil {
		t.Fatal(err)
	}
	var sector [renterhost.SectorSize]byte
	for i := range sector {
		sector[i] = byte(3*i*i + 5*i + 7)
	}
	for i := 0; i < 7; i++ {
		sector[0]++
		if _, err := sess.Append(&sector); err != nil {
			t.Fatal(err)
		}
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}

	// TODO: renew contract here; host SHOULD still submit finalization for old
	// contract, but SHOULD NOT attempt to submit a storage proof

	// mine until the proof window begins; host should submit finalization
	// transaction before then
	for renterNode.height() < rev.EndHeight() {
		if txns := hostNode.tp.TransactionList(); len(txns) == 1 && len(txns[len(txns)-1].FileContractRevisions) == 1 {
			break
		}
		renterNode.mineBlock()
		synchronize()
	}
	if txns := hostNode.tp.TransactionList(); len(txns) != 1 ||
		len(txns[len(txns)-1].FileContractRevisions) != 1 ||
		txns[len(txns)-1].FileContractRevisions[0].ParentID != rev.ID() {
		t.Fatal("host did not submit finalization transaction")
	}
	finalRev := hostNode.tp.TransactionList()[0].FileContractRevisions[0]
	// mine the remaining blocks
	for renterNode.height() <= rev.EndHeight() {
		if txns := hostNode.tp.TransactionList(); len(txns) == 1 && len(txns[len(txns)-1].StorageProofs) == 1 {
			break
		}
		// host should submit a storage proof transaction
		renterNode.mineBlock()
		synchronize()
	}
	if txns := hostNode.tp.TransactionList(); len(txns) != 1 ||
		len(txns[len(txns)-1].StorageProofs) != 1 ||
		txns[len(txns)-1].StorageProofs[0].ParentID != rev.ID() {
		t.Fatal("host did not submit storage proof")
	}

	// mine a block containing the storage proof, then continue mining until the
	// contract payout matures. The host's balance should increase accordingly.
	oldBalance := hostNode.balance()
	renterNode.mineBlock()
	renterNode.mineBlocks(types.MaturityDelay)
	synchronize()
	newBalance := hostNode.balance()
	if !newBalance.Equals(oldBalance.Add(finalRev.ValidHostPayout())) {
		t.Fatalf("expected %v, got %v", oldBalance.Add(finalRev.ValidHostPayout()), newBalance)
	}
}
