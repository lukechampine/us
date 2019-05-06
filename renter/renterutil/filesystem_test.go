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
	"lukechampine.com/us/renterhost"
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

func createTestingFS(tb testing.TB) (*PseudoFS, func()) {
	hosts := make([]*ghost.Host, 3)
	contracts := make(renter.ContractSet)
	hkr := make(testHKR)
	for i := range hosts {
		h, c := createHostWithContract(tb)
		hosts[i] = h
		contracts[h.PublicKey()] = c
		hkr[h.PublicKey()] = h.Settings().NetAddress
	}

	fs := NewFileSystem(os.TempDir(), contracts, hkr, 0)
	cleanup := func() {
		fs.Close()
		for _, h := range hosts {
			h.Close()
		}
	}
	return fs, cleanup
}

func TestFileSystemBasic(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	fs, cleanup := createTestingFS(t)
	defer cleanup()

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
			for i := 0; i < n; i++ {
				if p[i] != d[i] {
					t.Log(i)
					break
				}
			}
			t.Error("data from Read does not match actual data")
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

func TestFileSystemUploadDir(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	fs, cleanup := createTestingFS(t)
	defer cleanup()

	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	// create three metafiles
	metaName1 := t.Name() + "-" + hex.EncodeToString(fastrand.Bytes(6))
	pf1, err := fs.Create(metaName1, 2)
	check(err)
	data1 := fastrand.Bytes(renterhost.SectorSize - 256)
	_, err = pf1.Write(data1)
	check(err)

	metaName2 := t.Name() + "-" + hex.EncodeToString(fastrand.Bytes(6))
	pf2, err := fs.Create(metaName2, 2)
	check(err)
	data2 := fastrand.Bytes(renterhost.SectorSize - 256)
	_, err = pf2.Write(data2)
	check(err)

	metaName3 := t.Name() + "-" + hex.EncodeToString(fastrand.Bytes(6))
	pf3, err := fs.Create(metaName3, 2)
	check(err)
	data3 := fastrand.Bytes(renterhost.SectorSize - 256)
	_, err = pf3.Write(data3)
	check(err)

	// sync and close all files
	check(pf1.Sync())
	check(pf1.Close())
	check(pf2.Sync())
	check(pf2.Close())
	check(pf3.Sync())
	check(pf3.Close())

	// open files for reading and verify contents
	checkContents := func(name string, data []byte) {
		t.Helper()
		pf, err := fs.Open(name)
		check(err)
		p := make([]byte, len(data))
		_, err = pf.ReadAt(p, 0)
		check(err)
		if !bytes.Equal(p, data) {
			t.Error("contents do not match data")
		}
		check(pf.Close())
	}
	checkContents(metaName1, data1)
	checkContents(metaName2, data2)
	checkContents(metaName3, data3)

	// remove files
	if err := fs.Remove(metaName1); err != nil {
		t.Fatal(err)
	}
	if err := fs.Remove(metaName2); err != nil {
		t.Fatal(err)
	}
	if err := fs.Remove(metaName3); err != nil {
		t.Fatal(err)
	}
}

func TestFileSystemRandomAccess(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	t.Skip("WriteAt not implemented")

	fs, cleanup := createTestingFS(t)
	defer cleanup()

	// create metafile
	metaName := t.Name() + "-" + hex.EncodeToString(fastrand.Bytes(6))
	pf, err := fs.Create(metaName, 2)
	if err != nil {
		t.Fatal(err)
	}

	// perform three overlapping writes
	data1 := fastrand.Bytes(256)
	data2 := fastrand.Bytes(256)
	data3 := fastrand.Bytes(256)
	if _, err := pf.WriteAt(data1, 0); err != nil {
		t.Fatal(err)
	} else if _, err := pf.WriteAt(data2, 250); err != nil {
		t.Fatal(err)
	} else if _, err := pf.WriteAt(data3, 129); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 506)
	copy(data, data1)
	copy(data[250:], data2)
	copy(data[129:], data3)

	// truncate
	data = data[:len(data)-13]
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

	// open file for reading
	pf, err = fs.Open("foo")
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()

	// read and seek within file
	p := make([]byte, stat.Size())
	checkRead := func(d []byte) {
		t.Helper()
		if n, err := pf.Read(p[:len(d)]); err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(p[:n], d) {
			if n > 50 {
				n = 50
			}
			t.Log(p[:n])
			t.Log(d[:n])
			t.Error("data from Read does not match actual data")
		}
	}
	checkRead(data[:10])
	checkRead(data[10:150])
	checkRead(data[150:256])
	checkRead(data[256:506])

	// remove file
	if err := pf.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fs.Remove(pf.Name()); err != nil {
		t.Fatal(err)
	}
}
