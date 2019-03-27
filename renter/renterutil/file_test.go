package renterutil

import (
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"gitlab.com/NebulousLabs/fastrand"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/internal/ed25519"
	"lukechampine.com/us/internal/ghost"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/proto"
)

type stubWallet struct{}

func (stubWallet) NewWalletAddress() (uh types.UnlockHash, err error)                       { return }
func (stubWallet) SignTransaction(*types.Transaction, []crypto.Hash) (err error)            { return }
func (stubWallet) UnspentOutputs() (us []modules.UnspentOutput, err error)                  { return }
func (stubWallet) UnlockConditions(types.UnlockHash) (uc types.UnlockConditions, err error) { return }

type stubTpool struct{}

func (stubTpool) AcceptTransactionSet([]types.Transaction) (err error) { return }
func (stubTpool) FeeEstimate() (min, max types.Currency, err error)    { return }

type testHKR map[hostdb.HostPublicKey]modules.NetAddress

func (hkr testHKR) ResolveHostKey(pubkey hostdb.HostPublicKey) (modules.NetAddress, error) {
	return hkr[pubkey], nil
}

// createTestingPair creates a renter and host, initiates a Session between
// them, and forms and locks a contract.
func createHostWithContract(tb testing.TB) (*ghost.Host, *renter.Contract) {
	host, err := ghost.New()
	if err != nil {
		tb.Fatal(err)
	}
	sh := hostdb.ScannedHost{
		HostSettings: host.Settings(),
		PublicKey:    host.PublicKey(),
	}

	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	contractRevision, err := proto.FormContract(stubWallet{}, stubTpool{}, key, sh, types.ZeroCurrency, 0, 0)
	if err != nil {
		tb.Fatal(err)
	}
	contractPath := filepath.Join(os.TempDir(), tb.Name()+"-"+hex.EncodeToString(fastrand.Bytes(6))+".contract")
	if err := renter.SaveContract(contractRevision, key, contractPath); err != nil {
		tb.Fatal(err)
	}
	contract, err := renter.LoadContract(contractPath)
	if err != nil {
		tb.Fatal(err)
	}
	return host, contract
}

func TestFile(t *testing.T) {
	// create three hosts and form contracts with each of them
	hosts := make([]*ghost.Host, 3)
	contracts := make(renter.ContractSet)
	hkr := make(testHKR)
	for i := range hosts {
		h, c := createHostWithContract(t)
		hosts[i] = h
		contracts[h.PublicKey()] = c
		hkr[h.PublicKey()] = h.Settings().NetAddress
	}

	// create test data and encode it in a 2-of-3 scheme
	data := fastrand.Bytes(4096 * 2)
	rsc := renter.NewRSCode(2, 3)
	shards := make([][]byte, 3)
	for i := range shards {
		shards[i] = make([]byte, 4096)
	}
	rsc.Encode(data, shards)

	// create metafile
	metaPath := filepath.Join(os.TempDir(), t.Name()+"-"+hex.EncodeToString(fastrand.Bytes(6))+".usa")
	m, err := renter.NewMetaFile(metaPath, 0777, int64(len(data)), contracts, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	// upload to hosts, using lots of small, weird SectorSlices (instead of
	// uniform SectorSize-sized ones) to test that edge cases are being handled
	for i, hostKey := range m.Hosts {
		u, err := renter.NewShardUploader(m, contracts[hostKey], hkr, 0)
		if err != nil {
			t.Fatal(err)
		}
		buf := bytes.NewBuffer(shards[i])
		u.Sector.Append(buf.Next(merkle.SegmentSize), m.MasterKey)
		u.Sector.Append(buf.Next(merkle.SegmentSize*7), m.MasterKey)
		u.Sector.Append(buf.Next(merkle.SegmentSize*4), m.MasterKey)
		if err := u.Upload(0); err != nil {
			t.Fatal(err)
		}
		u.Sector.Reset()
		u.Sector.Append(buf.Bytes(), m.MasterKey)
		if err := u.Upload(3); err != nil {
			t.Fatal(err)
		}
		u.Close()
	}

	// create downloader set and pseudofile
	ds, err := NewDownloaderSet(contracts, hkr)
	if err != nil {
		t.Fatal(err)
	}
	defer ds.Close()
	pf, err := NewPseudoFile(m, ds)
	if err != nil {
		t.Fatal(err)
	}

	// begin file method tests
	p := make([]byte, m.Filesize)
	checkRead := func(d []byte) {
		if n, err := pf.Read(p[:len(d)]); err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(p[:n], d) {
			t.Fatal("data from Read does not match actual data")
		}
	}
	checkRead(data[:1024])
	checkRead(data[1024:2048])

	if _, err := pf.Seek(-2048, io.SeekCurrent); err != nil {
		t.Fatal(err)
	}
	checkRead(data[:1024])

	if _, err := pf.Seek(1, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	checkRead(data[1 : 1+1024])

	// partial read at end
	if _, err := pf.Seek(500, io.SeekEnd); err != nil {
		t.Fatal(err)
	}
	if n, err := pf.Read(p); err != nil {
		t.Fatal(err)
	} else if n != 500 {
		t.Fatalf("expected to read 500 bytes, got %v", n)
	} else if !bytes.Equal(p[:n], data[len(data)-500:]) {
		t.Fatal("data from Read does not match actual data")
	}

	// truncate and read
	if err := pf.Truncate(1023); err != nil {
		t.Fatal(err)
	} else if _, err := pf.Seek(512, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	checkRead(data[512:1023])
}
