package renterutil

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"lukechampine.com/frand"
	"lukechampine.com/us/renter"
)

func TestMigrate(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	// create two HostSets with three hosts, where two of those hosts are shared
	hkr := make(testHKR)
	hs1 := NewHostSet(hkr, 0)
	hs2 := NewHostSet(hkr, 0)
	for i := 0; i < 2; i++ {
		h, c := createHostWithContract(t)
		defer h.Close()
		hkr[h.PublicKey()] = h.Settings().NetAddress
		hs1.AddHost(c)
		hs2.AddHost(c)
	}
	// add one host only to hs1
	h, c := createHostWithContract(t)
	defer h.Close()
	hkr[h.PublicKey()] = h.Settings().NetAddress
	hs1.AddHost(c)
	// add one host only to hs2
	h, c = createHostWithContract(t)
	defer h.Close()
	hkr[h.PublicKey()] = h.Settings().NetAddress
	hs2.AddHost(c)

	// create fs1 with hs1
	fs1 := NewFileSystem(os.TempDir(), hs1)
	defer fs1.Close()

	// create metafile
	metaName := t.Name() + "-" + hex.EncodeToString(frand.Bytes(6))
	pf, err := fs1.Create(metaName, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()
	// write some data
	data := []byte("one two three four five")
	if _, err := pf.Write(data); err != nil {
		t.Fatal(err)
	}
	// flush data to hosts and close
	if err := pf.Sync(); err != nil {
		t.Fatal(err)
	} else if err := pf.Close(); err != nil {
		t.Fatal(err)
	}
	// reopen for reading, for migration
	pf, err = fs1.Open(metaName)
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()

	// migrate file to hs2
	metaPath := filepath.Join(fs1.root, metaName) + ".usa"
	m, err := renter.ReadMetaFile(metaPath)
	if err != nil {
		t.Fatal(err)
	}

	migrator := NewMigrator(hs2)
	if !migrator.NeedsMigrate(m) {
		t.Error("migrator should recognize metafile as requiring migration")
	}
	err = migrator.AddFile(m, pf, func(newM *renter.MetaFile) error {
		return renter.WriteMetaFile(metaPath, newM)
	})
	if err != nil {
		t.Fatal(err)
	} else if err := migrator.Flush(); err != nil {
		t.Fatal(err)
	}

	// create fs2 with hs2
	fs2 := NewFileSystem(os.TempDir(), hs2)
	defer fs2.Close()

	// close one of the non-hs2 hosts; this ensures that we'll download from the new host
	for hostKey, lh := range fs1.hosts.sessions {
		if fs2.hosts.HasHost(hostKey) {
			lh.s.Close()
			delete(fs2.hosts.sessions, hostKey)
			break
		}
	}

	// download using new host set
	pf, err = fs2.Open(metaName)
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()
	read, err := ioutil.ReadAll(pf)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(read, data) {
		t.Fatal("contents do not match data")
	}

	// all hosts should have same number of sectors (since we should not have
	// reuploaded anything to shared hosts)
	for hostKey := range hs2.sessions {
		h, err := hs2.acquire(hostKey)
		if err != nil {
			t.Fatal(err)
		}
		defer hs2.release(hostKey)
		if h.Revision().NumSectors() != 1 {
			t.Fatalf("expected %v stored sectors, got %v", 1, h.Revision().NumSectors())
		}
	}
}
