package renter

import (
	"io"
	"os"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/ed25519"
	"lukechampine.com/us/hostdb"
)

const (
	// ContractMagic is the magic string that identifies contract files.
	ContractMagic = "us-contract"

	// ContractSize is the size in bytes of the contract file header.
	// It is also the offset at which the contract revision data begins.
	ContractSize = 11 + 1 + 32 + 32 + 32

	// ContractVersion is the current version of the contract file format. It is
	// incremented after each change to the format.
	ContractVersion uint8 = 4
)

// A Contract identifies a unique file contract and possess the secret key that
// can revise it.
type Contract struct {
	HostKey   hostdb.HostPublicKey
	ID        types.FileContractID
	RenterKey ed25519.PrivateKey
}

// SaveContract creates a new contract file using the provided contract.
func SaveContract(c Contract, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return errors.Wrap(err, "could not create contract file")
	}
	defer f.Close()
	buf := make([]byte, ContractSize)
	copy(buf[0:11], ContractMagic)
	buf[11] = ContractVersion
	copy(buf[12:44], c.HostKey.Ed25519())
	copy(buf[44:76], c.ID[:])
	copy(buf[76:108], c.RenterKey[:ed25519.SeedSize])
	if _, err := f.Write(buf); err != nil {
		return errors.Wrap(err, "could not write contract header and revision")
	} else if err := f.Sync(); err != nil {
		return errors.Wrap(err, "could not sync contract file")
	}
	return nil
}

// LoadContract loads a contract file into memory.
func LoadContract(filename string) (c Contract, err error) {
	f, err := os.OpenFile(filename, os.O_RDWR, 0)
	if err != nil {
		return Contract{}, errors.Wrap(err, "could not open contract file")
	}
	defer f.Close()

	buf := make([]byte, ContractSize)
	if _, err := io.ReadFull(f, buf); err != nil {
		return Contract{}, errors.Wrap(err, "could not read contract")
	}
	magic := string(buf[0:11])
	version := buf[11]
	c.HostKey = hostdb.HostKeyFromPublicKey(buf[12:44])
	copy(c.ID[:], buf[44:76])
	c.RenterKey = ed25519.NewKeyFromSeed(buf[76:108])

	if magic != ContractMagic {
		return Contract{}, errors.Errorf("contract is invalid: wrong magic bytes (%q)", magic)
	}
	if version != ContractVersion {
		return Contract{}, errors.Errorf("contract is invalid: incompatible version (v%d): convert to v%d", version, ContractVersion)
	}

	return c, nil
}

// A ContractSet is a map of Contracts keyed by their host public key.
type ContractSet map[hostdb.HostPublicKey]Contract
