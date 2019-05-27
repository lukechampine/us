package proto

import (
	"bytes"
	"io/ioutil"
	"testing"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/encoding"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"gitlab.com/NebulousLabs/fastrand"
	"lukechampine.com/us/ed25519"
	"lukechampine.com/us/internal/ghost"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renterhost"
)

func deepEqual(a, b interface{}) bool {
	return bytes.Equal(encoding.Marshal(a), encoding.Marshal(b))
}

type stubWallet struct{}

func (stubWallet) NewWalletAddress() (uh types.UnlockHash, err error)                       { return }
func (stubWallet) SignTransaction(*types.Transaction, []crypto.Hash) (err error)            { return }
func (stubWallet) UnspentOutputs() (us []modules.UnspentOutput, err error)                  { return }
func (stubWallet) UnlockConditions(types.UnlockHash) (uc types.UnlockConditions, err error) { return }

type stubTpool struct{}

func (stubTpool) AcceptTransactionSet([]types.Transaction) (err error) { return }
func (stubTpool) FeeEstimate() (min, max types.Currency, err error)    { return }

type contractEditor struct {
	rev ContractRevision
	key ed25519.PrivateKey
}

func (e *contractEditor) Revision() ContractRevision { return e.rev }
func (e *contractEditor) Key() ed25519.PrivateKey    { return e.key }
func (e *contractEditor) SetRevision(rev ContractRevision) error {
	e.rev = rev
	return nil
}

// createTestingPair creates a renter and host, initiates a Session between
// them, and forms and locks a contract.
func createTestingPair(tb testing.TB) (*Session, *ghost.Host) {
	tb.Helper()

	host, err := ghost.New(":0")
	if err != nil {
		tb.Fatal(err)
	}

	s, err := NewUnlockedSession(host.Settings().NetAddress, host.PublicKey(), 0)
	if err != nil {
		tb.Fatal(err)
	}

	settings, err := s.Settings()
	if err != nil {
		tb.Fatal(err)
	}
	if !deepEqual(settings, host.Settings()) {
		tb.Fatal("received settings do not match host's actual settings")
	}

	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	contractRevision, err := s.FormContract(stubWallet{}, stubTpool{}, key, types.ZeroCurrency, 0, 0)
	if err != nil {
		tb.Fatal(err)
	}
	contract := &contractEditor{contractRevision, key}
	err = s.Lock(contract)
	if err != nil {
		tb.Fatal(err)
	}
	return s, host
}

func TestSession(t *testing.T) {
	renter, host := createTestingPair(t)
	defer renter.Close()
	defer host.Close()

	var sector [renterhost.SectorSize]byte
	fastrand.Read(sector[:])
	sectorRoot := merkle.SectorRoot(&sector)

	err := renter.Write([]renterhost.RPCWriteAction{{
		Type: renterhost.RPCWriteActionAppend,
		Data: sector[:],
	}})
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
	sectorBuf.Grow(renterhost.SectorSize)
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

func BenchmarkWrite(b *testing.B) {
	renter, host := createTestingPair(b)
	defer renter.Close()
	defer host.Close()

	sector := fastrand.Bytes(renterhost.SectorSize)

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(renterhost.SectorSize)

	for i := 0; i < b.N; i++ {
		err := renter.Write([]renterhost.RPCWriteAction{{
			Type: renterhost.RPCWriteActionAppend,
			Data: sector,
		}})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRead(b *testing.B) {
	renter, host := createTestingPair(b)
	defer renter.Close()
	defer host.Close()

	var sector [renterhost.SectorSize]byte
	fastrand.Read(sector[:])
	sectorRoot := merkle.SectorRoot(&sector)
	err := renter.Write([]renterhost.RPCWriteAction{{
		Type: renterhost.RPCWriteActionAppend,
		Data: sector[:],
	}})
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(renterhost.SectorSize)

	for i := 0; i < b.N; i++ {
		err = renter.Read(ioutil.Discard, []renterhost.RPCReadRequestSection{{
			MerkleRoot: sectorRoot,
			Offset:     0,
			Length:     renterhost.SectorSize,
		}})
		if err != nil {
			b.Fatal(err)
		}
	}
}
