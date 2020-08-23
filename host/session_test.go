package host_test

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/internal/ghost"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renterhost"
)

type stubWallet struct{}

func (stubWallet) Address() (_ types.UnlockHash, _ error) { return }
func (stubWallet) FundTransaction(*types.Transaction, types.Currency) (_ []crypto.Hash, _ error) {
	return
}
func (stubWallet) SignTransaction(txn *types.Transaction, toSign []crypto.Hash) error {
	txn.TransactionSignatures = append(txn.TransactionSignatures, make([]types.TransactionSignature, len(toSign))...)
	return nil
}

type stubTpool struct{}

func (stubTpool) AcceptTransactionSet([]types.Transaction) (_ error)                    { return }
func (stubTpool) UnconfirmedParents(types.Transaction) (_ []types.Transaction, _ error) { return }
func (stubTpool) FeeEstimate() (_, _ types.Currency, _ error)                           { return }

// createTestingPair creates a renter and host, initiates a Session between
// them, and forms and locks a contract.
func createTestingPair(tb testing.TB) (*proto.Session, *ghost.Host) {
	tb.Helper()

	host := ghost.New(tb, stubWallet{}, stubTpool{})

	s, err := proto.NewUnlockedSession(host.Settings.NetAddress, host.PublicKey, 0)
	if err != nil {
		tb.Fatal(err)
	}

	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	rev, _, err := s.FormContract(stubWallet{}, stubTpool{}, key, types.ZeroCurrency, 0, 0)
	if err != nil {
		tb.Fatal(err)
	}
	err = s.Lock(rev.ID(), key, 0)
	if err != nil {
		tb.Fatal(err)
	}
	return s, host
}

func TestSession(t *testing.T) {
	renter, host := createTestingPair(t)
	defer renter.Close()
	defer host.Close()

	sector := [renterhost.SectorSize]byte{0: 1}
	sectorRoot, err := renter.Append(&sector)
	if err != nil {
		t.Fatal(err)
	}

	roots, err := renter.SectorRoots(0, 1)
	if err != nil {
		t.Fatal(err)
	} else if roots[0] != sectorRoot {
		t.Fatal("reported sector root does not match actual sector root")
	}

	var sectorBuf bytes.Buffer
	err = renter.Read(&sectorBuf, []renterhost.RPCReadRequestSection{{
		MerkleRoot: sectorRoot,
		Offset:     0,
		Length:     renterhost.SectorSize,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sectorBuf.Bytes(), sector[:]) {
		t.Fatal("downloaded sector does not match uploaded sector")
	}

	err = renter.Unlock()
	if err != nil {
		t.Fatal(err)
	}
}
