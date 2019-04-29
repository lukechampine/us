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
	host, err := ghost.New(":0")
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

func TestFileSystem(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

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

	// create filesystem
	fs := NewFileSystem(os.TempDir(), contracts, hkr, 0)
	defer fs.Close()

	// create metafile
	metaName := t.Name() + "-" + hex.EncodeToString(fastrand.Bytes(6))
	pf, err := fs.Create(metaName, 2)
	if err != nil {
		t.Fatal(err)
	}
	// fill file with random data, using lots of small, weird SectorSlices
	// (instead of uniform SectorSize-sized ones) to test that edge cases are
	// being handled
	sizes := []int{64, 127, 12, 4096, 253}
	var data []byte
	for i, size := range sizes {
		d := fastrand.Bytes(size)
		if _, err := pf.Write(d); err != nil {
			t.Fatal(err)
		}
		data = append(data, d...)
		// flush after every other Write, to test padding
		if i%2 == 1 {
			if err := pf.Sync(); err != nil {
				t.Fatal(err)
			}
		}
	}

	// truncate uncommitted data
	data = data[:len(data)-13]
	if err := pf.Truncate(int64(len(data))); err != nil {
		t.Fatal(err)
	}
	// truncate committed data
	data = data[:len(data)-253]
	if err := pf.Truncate(int64(len(data))); err != nil {
		t.Fatal(err)
	}

	// close file
	if err := pf.Close(); err != nil {
		t.Fatal(err)
	}

	// stat file
	stat, err := fs.Stat(metaName)
	if err != nil {
		t.Fatal(err)
	} else if stat.Name() != metaName {
		t.Error("incorrect name")
	} else if stat.Size() != int64(len(data)) {
		t.Error("incorrect size")
	} else if stat.Mode() != 0666 {
		t.Error("incorrect mode")
	}

	// rename file
	err = fs.Rename(metaName, "foo")
	if err != nil {
		t.Fatal(err)
	}

	// chmod file
	err = fs.Chmod("foo", 0676)
	if err != nil {
		t.Fatal(err)
	}

	// open file for reading
	pf, err = fs.Open("foo")
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()

	// stat file (this time via method)
	stat, err = pf.Stat()
	if err != nil {
		t.Fatal(err)
	} else if stat.Name() != "foo" || stat.Name() != pf.Name() {
		t.Error("incorrect name")
	} else if stat.Size() != int64(len(data)) {
		t.Error("incorrect size")
	} else if stat.Mode() != 0676 {
		t.Error("incorrect mode")
	}

	// read and seek within file
	p := make([]byte, stat.Size())
	checkRead := func(d []byte) {
		t.Helper()
		if n, err := pf.Read(p[:len(d)]); err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(p[:n], d) {
			t.Fatal("data from Read does not match actual data")
		}
	}
	checkRead(data[:10])
	checkRead(data[10:150])
	checkRead(data[150:1024])
	checkRead(data[1024:1530])
	checkRead(data[1530:2048])

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
	// with ReadAt, partial read should return io.EOF
	if n, err := pf.ReadAt(p, stat.Size()-500); err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	} else if n != 500 {
		t.Fatalf("expected to read 500 bytes, got %v", n)
	}

	// remove file
	if err := pf.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fs.Remove(pf.Name()); err != nil {
		t.Fatal(err)
	}
}
