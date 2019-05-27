package renter

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/ed25519"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter/proto"
)

const (
	// ContractMagic is the magic string that identifies contract files.
	ContractMagic = "us-contract"

	// ContractHeaderSize is the size in bytes of the contract file header.
	// It is also the offset at which the contract revision data begins.
	ContractHeaderSize = 11 + 1 + 32 + 32 + 32

	// ContractSize is the maximum size in bytes of a contract file.
	ContractSize = 1024

	// ContractVersion is the current version of the contract file format. It is
	// incremented after each change to the format.
	ContractVersion uint8 = 3
)

// ContractHeader contains the data encoded within the first
// ContractHeaderSize bytes of the contract file.
type ContractHeader struct {
	magic   string
	version uint8
	hostKey hostdb.HostPublicKey
	id      types.FileContractID
	key     ed25519.PrivateKey
}

// Validate validates a ContractHeader, checking its magic bytes and version.
func (h *ContractHeader) Validate() error {
	if h.magic != ContractMagic {
		return errors.Errorf("wrong magic bytes (%q)", h.magic)
	}
	if h.version != ContractVersion {
		return errors.Errorf("incompatible version (v%d): convert to v%d", h.version, ContractVersion)
	}
	return nil
}

// A Contract represents an open contract file. Contract files contain all the
// data necessary to revise a file contract.
type Contract struct {
	proto.ContractRevision // for convenience
	header                 ContractHeader
	f                      *os.File
}

// Close closes the contract file.
func (c *Contract) Close() error {
	return c.f.Close()
}

// HostKey returns the public key of the contract's host.
func (c *Contract) HostKey() hostdb.HostPublicKey {
	return c.header.hostKey
}

// Revision returns the latest revision of the file contract.
func (c *Contract) Revision() proto.ContractRevision {
	return c.ContractRevision
}

// Key returns the renter's signing key.
func (c *Contract) Key() ed25519.PrivateKey {
	return c.header.key
}

// SetRevision sets the current revision of the file contract.
func (c *Contract) SetRevision(rev proto.ContractRevision) error {
	c.ContractRevision = rev
	if _, err := c.f.WriteAt(marshalRevision(c.ContractRevision), ContractHeaderSize); err != nil {
		return errors.Wrap(err, "could not write contract revision")
	}
	return nil
}

func marshalHeader(rev proto.ContractRevision, key ed25519.PrivateKey) []byte {
	buf := bytes.NewBuffer(make([]byte, 0, ContractHeaderSize))
	buf.WriteString(ContractMagic)
	buf.WriteByte(ContractVersion)
	buf.Write(rev.HostKey().Ed25519())
	buf.Write(rev.Revision.ParentID[:])
	buf.Write(key[:ed25519.SeedSize])
	return buf.Bytes()
}

func unmarshalHeader(b []byte) (h ContractHeader) {
	buf := bytes.NewBuffer(b)
	h.magic = string(buf.Next(len(ContractMagic)))
	h.version, _ = buf.ReadByte()
	h.hostKey = hostdb.HostPublicKey(types.SiaPublicKey{
		Algorithm: types.SignatureEd25519,
		Key:       buf.Next(32),
	}.String())
	copy(h.id[:], buf.Next(32))
	h.key = ed25519.NewKeyFromSeed(buf.Next(32))
	return h
}

func marshalRevision(rev proto.ContractRevision) []byte {
	var buf bytes.Buffer
	buf.Grow(ContractSize)
	rev.Revision.MarshalSia(&buf)
	rev.Signatures[0].MarshalSia(&buf)
	rev.Signatures[1].MarshalSia(&buf)
	return buf.Bytes()
}

func unmarshalRevision(b []byte, rev *proto.ContractRevision) error {
	buf := bytes.NewBuffer(b)
	if err := rev.Revision.UnmarshalSia(buf); err != nil {
		return err
	} else if err := rev.Signatures[0].UnmarshalSia(buf); err != nil {
		return err
	} else if err := rev.Signatures[1].UnmarshalSia(buf); err != nil {
		return err
	}
	return nil
}

// SaveContract creates a new contract file using the provided contract.
func SaveContract(contract proto.ContractRevision, key ed25519.PrivateKey, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return errors.Wrap(err, "could not create contract file")
	}
	defer f.Close()
	buf := make([]byte, ContractSize)
	copy(buf, marshalHeader(contract, key))
	copy(buf[ContractHeaderSize:], marshalRevision(contract))
	if _, err := f.Write(buf); err != nil {
		return errors.Wrap(err, "could not write contract header and revision")
	} else if err := f.Sync(); err != nil {
		return errors.Wrap(err, "could not sync contract file")
	}
	return nil
}

// SaveRenewedContract creates a new contract file using the provided contract.
func SaveRenewedContract(oldContract *Contract, newContract proto.ContractRevision, filename string) error {
	return SaveContract(newContract, oldContract.header.key, filename)
}

// LoadContract loads a contract file into memory.
func LoadContract(filename string) (_ *Contract, err error) {
	f, err := os.OpenFile(filename, os.O_RDWR, 0)
	if err != nil {
		return nil, errors.Wrap(err, "could not open contract file")
	}
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	b := make([]byte, ContractSize)
	if _, err := io.ReadFull(f, b); err != nil {
		return nil, errors.Wrap(err, "could not read contract")
	}
	header := unmarshalHeader(b[:ContractHeaderSize])
	if err := header.Validate(); err != nil {
		return nil, errors.Wrap(err, "contract is invalid")
	}

	// decode revision
	// TODO: try to recover if revision is invalid?
	var rev proto.ContractRevision
	err = unmarshalRevision(b[ContractHeaderSize:], &rev)
	if err != nil {
		return nil, err
	} else if !rev.IsValid() {
		return nil, errors.New("contract revision is invalid")
	} else if rev.HostKey() != header.hostKey {
		return nil, errors.New("contract revision has wrong host public key")
	} else if rev.ID() != header.id {
		return nil, errors.New("contract revision has wrong ID")
	}

	return &Contract{
		ContractRevision: rev,
		header:           header,
		f:                f,
	}, nil
}

// ReadContractRevision reads, decodes, and returns the ContractRevision
// of a contract file. The ContractRevision is not validated.
func ReadContractRevision(filename string) (proto.ContractRevision, error) {
	f, err := os.Open(filename)
	if err != nil {
		return proto.ContractRevision{}, errors.Wrap(err, "could not open contract file")
	}
	defer f.Close()
	b := make([]byte, ContractSize)
	if _, err := f.ReadAt(b, 0); err != nil {
		return proto.ContractRevision{}, errors.Wrap(err, "could not read revision")
	}
	var rev proto.ContractRevision
	err = unmarshalRevision(b[ContractHeaderSize:], &rev)
	return rev, err
}

// A ContractSet is a map of Contracts keyed by their host public key.
type ContractSet map[hostdb.HostPublicKey]*Contract

// Close closes all the Contracts in the set.
func (set ContractSet) Close() error {
	for _, c := range set {
		c.Close()
	}
	return nil
}

// LoadContracts loads a set of contract files stored in a directory and
// returns a map that keys the contracts by their host key. Files not ending
// in .contract are ignored. If multiple contracts have the same host key,
// LoadContracts returns an error.
func LoadContracts(dir string) (ContractSet, error) {
	d, err := os.Open(dir)
	if err != nil {
		return nil, errors.Wrap(err, "could not open contract dir")
	}
	defer d.Close()
	filenames, err := d.Readdirnames(-1)
	if err != nil {
		return nil, errors.Wrap(err, "could not read contract dir")
	}
	contracts := make(ContractSet, len(filenames))
	for _, file := range filenames {
		if filepath.Ext(file) != ".contract" {
			continue
		}
		c, err := LoadContract(filepath.Join(dir, file))
		if err != nil {
			contracts.Close()
			return nil, errors.Wrapf(err, "could not load contract %v", file)
		} else if _, ok := contracts[c.HostKey()]; ok {
			contracts.Close()
			return nil, errors.Errorf("multiple contracts for host %v", c.HostKey().ShortKey())
		}
		contracts[c.HostKey()] = c
	}
	return contracts, nil
}
