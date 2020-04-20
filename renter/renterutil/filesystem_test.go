package renterutil

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/frand"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/internal/ghost"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renterhost"
)

type stubWallet struct{}

func (stubWallet) NewWalletAddress() (uh types.UnlockHash, err error)                       { return }
func (stubWallet) SignTransaction(*types.Transaction, []crypto.Hash) (err error)            { return }
func (stubWallet) UnspentOutputs(bool) (us []modules.UnspentOutput, err error)              { return }
func (stubWallet) UnconfirmedParents(types.Transaction) (ps []types.Transaction, err error) { return }
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
func createHostWithContract(tb testing.TB) (*ghost.Host, renter.Contract) {
	host, err := ghost.New(":0")
	if err != nil {
		tb.Fatal(err)
	}
	sh := hostdb.ScannedHost{
		HostSettings: host.Settings(),
		PublicKey:    host.PublicKey(),
	}

	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	rev, _, err := proto.FormContract(stubWallet{}, stubTpool{}, key, sh, types.ZeroCurrency, 0, 0)
	if err != nil {
		tb.Fatal(err)
	}
	contract := renter.Contract{
		HostKey:   rev.HostKey(),
		ID:        rev.ID(),
		RenterKey: key,
	}
	return host, contract
}

func createTestingFS(tb testing.TB, numHosts int) (*PseudoFS, func()) {
	hosts := make([]*ghost.Host, numHosts)
	hkr := make(testHKR)
	hs := NewHostSet(hkr, 0)
	for i := range hosts {
		h, c := createHostWithContract(tb)
		hosts[i] = h
		hkr[h.PublicKey()] = h.Settings().NetAddress
		hs.AddHost(c)
	}

	fs := NewFileSystem(os.TempDir(), hs)
	cleanup := func() {
		fs.Close()
		for _, h := range hosts {
			h.Close()
		}
	}
	return fs, cleanup
}

func TestHostErrorSet(t *testing.T) {
	hosts := make([]*ghost.Host, 3)
	hkr := make(testHKR)
	hs := NewHostSet(hkr, 0)
	for i := range hosts {
		h, c := createHostWithContract(t)
		hosts[i] = h
		hkr[h.PublicKey()] = h.Settings().NetAddress
		hs.AddHost(c)
		h.Close()
	}

	fs := NewFileSystem(os.TempDir(), hs)
	defer func() {
		fs.Close()
		for _, h := range hosts {
			h.Close()
		}
	}()

	metaName := t.Name() + "-" + hex.EncodeToString(frand.Bytes(6))
	pf, err := fs.Create(metaName, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pf.Write([]byte("foo")); err != nil {
		t.Fatal(err)
	}
	// should get a HostErrorSet when we sync
	err = pf.Sync()
	hes, ok := errors.Cause(err).(HostErrorSet)
	if !ok || hes == nil {
		t.Fatal("expected HostSetError, got", errors.Cause(err))
	} else if len(hes) != 3 {
		t.Fatal("expected HostSetError to have three hosts, got", len(hes))
	}
}

func TestFileSystemBasic(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	fs, cleanup := createTestingFS(t, 3)
	defer cleanup()

	// create metafile
	metaName := t.Name() + "-" + hex.EncodeToString(frand.Bytes(6))
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
		d := frand.Bytes(size)
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
		t.Error("incorrect size", stat.Size(), len(data))
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
		t.Error("incorrect size", stat.Size(), len(data))
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
	// ReadAtP should behave the same as ReadAt
	if n, err := pf.ReadAtP(p, stat.Size()-500); err != io.EOF {
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

	fs, cleanup := createTestingFS(t, 3)
	defer cleanup()

	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	// create three metafiles
	metaName1 := t.Name() + "-" + hex.EncodeToString(frand.Bytes(6))
	pf1, err := fs.Create(metaName1, 2)
	check(err)
	data1 := frand.Bytes(renterhost.SectorSize - 256)
	_, err = pf1.Write(data1)
	check(err)

	metaName2 := t.Name() + "-" + hex.EncodeToString(frand.Bytes(6))
	pf2, err := fs.Create(metaName2, 2)
	check(err)
	data2 := frand.Bytes(renterhost.SectorSize - 256)
	_, err = pf2.Write(data2)
	check(err)

	metaName3 := t.Name() + "-" + hex.EncodeToString(frand.Bytes(6))
	pf3, err := fs.Create(metaName3, 2)
	check(err)
	data3 := frand.Bytes(renterhost.SectorSize - 256)
	_, err = pf3.Write(data3)
	check(err)

	// close all files
	check(pf1.Close())
	check(pf2.Close())
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

func TestFileSystemLargeWrite(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	fs, cleanup := createTestingFS(t, 3)
	defer cleanup()

	// create metafile
	metaName := t.Name() + "-" + hex.EncodeToString(frand.Bytes(6))
	pf, err := fs.Create(metaName, 1)
	if err != nil {
		t.Fatal(err)
	}
	// write just over 1 sector
	data := frand.Bytes(renterhost.SectorSize + 1)
	if _, err = pf.Write(data); err != nil {
		t.Fatal(err)
	}

	// check contents
	p := make([]byte, len(data))
	if _, err := pf.ReadAt(p, 0); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(p, data) {
		t.Error("contents do not match data")
	}

	// sync and check again
	if err := pf.Sync(); err != nil {
		t.Fatal(err)
	} else if _, err := pf.ReadAt(p, 0); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(p, data) {
		t.Error("contents do not match data")
	}

	// close and cleanup
	if err := pf.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fs.Remove(metaName); err != nil {
		t.Fatal(err)
	}
}

func TestFileSystemTruncate(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	fs, cleanup := createTestingFS(t, 3)
	defer cleanup()

	// create metafile
	metaName := t.Name() + "-" + hex.EncodeToString(frand.Bytes(6))
	pf, err := fs.Create(metaName, 2)
	if err != nil {
		t.Fatal(err)
	}
	// write some data
	if _, err := pf.Write([]byte("one two three four five")); err != nil {
		t.Fatal(err)
	}
	// extend with zeros via Truncate
	if err := pf.Truncate(1000); err != nil {
		t.Fatal(err)
	}
	// check size via Stat
	if stat, err := pf.Stat(); err != nil {
		t.Fatal(err)
	} else if stat.Size() != 1000 {
		t.Error("incorrect size")
	}

	// check contents
	data := make([]byte, 1000)
	copy(data, "one two three four five")
	p := make([]byte, len(data))
	if _, err := pf.ReadAt(p, 0); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(p, data) {
		t.Error("contents do not match data")
	}

	// sync and check again
	if err := pf.Sync(); err != nil {
		t.Fatal(err)
	} else if _, err := pf.ReadAt(p, 0); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(p, data) {
		t.Error("contents do not match data")
	}

	// close and cleanup
	if err := pf.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fs.Remove(metaName); err != nil {
		t.Fatal(err)
	}
}

func TestFileSystemRandomAccess(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	fs, cleanup := createTestingFS(t, 3)
	defer cleanup()

	// create metafile
	metaName := t.Name() + "-" + hex.EncodeToString(frand.Bytes(6))
	pf, err := fs.Create(metaName, 2)
	if err != nil {
		t.Fatal(err)
	}

	checkContents := func(str string) {
		t.Helper()
		p := make([]byte, len(str))
		if _, err := pf.ReadAt(p, 0); err != nil {
			t.Fatal(err)
		} else if string(p) != str {
			t.Errorf("expected %q, got %q", str, string(p))
		}
	}

	// perform initial write
	if _, err := pf.Write([]byte("one two three four five")); err != nil {
		t.Fatal(err)
	} else if err := pf.Sync(); err != nil {
		t.Fatal(err)
	}
	checkContents("one two three four five")

	// overwrite every other word
	if _, err := pf.WriteAt([]byte("ten"), 0); err != nil {
		t.Fatal(err)
	} else if _, err := pf.WriteAt([]byte("seven"), 8); err != nil {
		t.Fatal(err)
	} else if _, err := pf.WriteAt([]byte("nine"), 19); err != nil {
		t.Fatal(err)
	}
	checkContents("ten two seven four nine")

	// sync and check again
	if err := pf.Sync(); err != nil {
		t.Fatal(err)
	}
	checkContents("ten two seven four nine")

	// write a full chunk, then a few more overlapping writes, using Seek
	// instead of WriteAt
	data := frand.Bytes(renterhost.SectorSize * 2)
	if _, err := pf.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	} else if _, err := pf.Write(data); err != nil {
		t.Fatal(err)
	} else if _, err := pf.Seek(renterhost.SectorSize, io.SeekStart); err != nil {
		t.Fatal(err)
	} else if _, err := pf.Write(data[:1024]); err != nil {
		t.Fatal(err)
	} else if _, err := pf.Seek(-10000, io.SeekCurrent); err != nil {
		t.Fatal(err)
	} else if _, err := pf.Write(data[:20000]); err != nil {
		t.Fatal(err)
	}

	// remove file
	if err := pf.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fs.Remove(pf.Name()); err != nil {
		t.Fatal(err)
	}
}

func TestFileSystemDelete(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	fs, cleanup := createTestingFS(t, 2)
	defer cleanup()

	expectStoredSectors := func(n int) {
		t.Helper()
		for hostKey := range fs.hosts.sessions {
			h, err := fs.hosts.acquire(hostKey)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.hosts.release(hostKey)
			if h.Revision().NumSectors() != n {
				t.Fatalf("expected %v stored sectors, got %v", n, h.Revision().NumSectors())
			}
			return
		}
		t.Fatal("couldn't connect to any hosts")
	}

	// create metafile
	metaName := t.Name() + "-" + hex.EncodeToString(frand.Bytes(6))
	pf, err := fs.Create(metaName, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()

	// write one full sector and one partial sector
	if _, err := pf.Write(make([]byte, renterhost.SectorSize+1024)); err != nil {
		t.Fatal(err)
	}
	expectStoredSectors(1)

	// Free the file; the full sector should be deleted, and the uncommitted
	// partial sector should be discarded
	if err := pf.Free(); err != nil {
		t.Fatal(err)
	}
	if info, _ := pf.Stat(); info.Size() != 0 {
		t.Fatal("filesize should be 0 after Free")
	}
	if n, err := pf.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatal("expected (0, EOF) when Reading after Free")
	}
	expectStoredSectors(0)

	// write another full sector and partial sector, but this time, flush the
	// partial sector
	if _, err := pf.Write(make([]byte, renterhost.SectorSize+1024)); err != nil {
		t.Fatal(err)
	} else if err := pf.Sync(); err != nil {
		t.Fatal(err)
	}

	// Free the file; the full sector should be deleted, but not the partial sector.
	if err := pf.Free(); err != nil {
		t.Fatal(err)
	}
	if info, _ := pf.Stat(); info.Size() != 0 {
		t.Fatal("filesize should be 0 after Free")
	}
	if n, err := pf.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatal("expected (0, EOF) when Reading after Free")
	}
	expectStoredSectors(1)

	// Close the file and Remove it, then run a GC; the partial sector should be
	// deleted.
	if err := pf.Close(); err != nil {
		t.Fatal(err)
	} else if err := fs.Remove(pf.Name()); err != nil {
		t.Fatal(err)
	} else if err := fs.GC(); err != nil {
		t.Fatal(err)
	}
	expectStoredSectors(0)

	// Upload two small files that share a sector.
	small1Name := t.Name() + "-" + hex.EncodeToString(frand.Bytes(6))
	small1, err := fs.Create(small1Name, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer small1.Close()
	if _, err := small1.Write([]byte("foo bar baz")); err != nil {
		t.Fatal(err)
	}
	small2Name := t.Name() + "-" + hex.EncodeToString(frand.Bytes(6))
	small2, err := fs.Create(small2Name, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer small2.Close()
	if _, err := small2.Write([]byte("foo bar baz")); err != nil {
		t.Fatal(err)
	}
	if err := small1.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := small2.Sync(); err != nil {
		t.Fatal(err)
	}
	expectStoredSectors(1)
	// calling Free on either file should no-op
	if err := small1.Free(); err != nil {
		t.Fatal(err)
	}
	if err := small2.Free(); err != nil {
		t.Fatal(err)
	}
	// Remove one of the files and GC; should no-op
	if err := small1.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fs.Remove(small1Name); err != nil {
		t.Fatal(err)
	}
	if err := fs.GC(); err != nil {
		t.Fatal(err)
	}
	expectStoredSectors(1)
	// Remove the other file and GC; should delete the sector
	if err := small2.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fs.Remove(small2Name); err != nil {
		t.Fatal(err)
	}
	if err := fs.GC(); err != nil {
		t.Fatal(err)
	}
	expectStoredSectors(0)
}

func BenchmarkFileSystemWrite(b *testing.B) {
	const numHosts = 4
	const minShards = 4
	fs, cleanup := createTestingFS(b, numHosts)
	defer cleanup()

	// create metafile
	metaName := b.Name() + "-" + hex.EncodeToString(frand.Bytes(6))
	pf, err := fs.Create(metaName, minShards)
	if err != nil {
		b.Fatal(err)
	}
	defer pf.Close()

	buf := make([]byte, renterhost.SectorSize*minShards)
	b.SetBytes(int64(len(buf)/minShards) * numHosts)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := pf.Write(buf); err != nil {
			b.Fatal(err)
		}
		// don't want to benchmark our cache
		if err := pf.Sync(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFileSystemRead(b *testing.B) {
	fs, cleanup := createTestingFS(b, 4)
	defer cleanup()

	// create metafile
	metaName := b.Name() + "-" + hex.EncodeToString(frand.Bytes(6))
	pf, err := fs.Create(metaName, 2)
	if err != nil {
		b.Fatal(err)
	}
	defer pf.Close()
	// upload initial data
	buf := make([]byte, renterhost.SectorSize)
	if _, err := pf.Write(buf); err != nil {
		b.Fatal(err)
	}
	if err := pf.Sync(); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := pf.Seek(0, io.SeekStart); err != nil {
			b.Fatal(err)
		}
		if _, err := pf.Read(buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFileSystemReadAtP(b *testing.B) {
	fs, cleanup := createTestingFS(b, 4)
	defer cleanup()

	// create metafile
	metaName := b.Name() + "-" + hex.EncodeToString(frand.Bytes(6))
	pf, err := fs.Create(metaName, 2)
	if err != nil {
		b.Fatal(err)
	}
	defer pf.Close()
	// upload initial data
	buf := make([]byte, renterhost.SectorSize)
	if _, err := pf.Write(buf); err != nil {
		b.Fatal(err)
	}
	if err := pf.Sync(); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := pf.ReadAtP(buf, 0)
		if err != nil {
			b.Fatal(err)
		}
	}
}
