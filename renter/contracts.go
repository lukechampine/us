package renter

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/types"
	"golang.org/x/crypto/ed25519"

	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renter/proto"
)

const (
	// ContractMagic is the magic string that identifies contract files.
	ContractMagic = "us-contract"

	// ContractHeaderSize is the size in bytes of the contract file header.
	// It is also the offset at which the contract revision data begins.
	ContractHeaderSize = 11 + 1 + 32 + 32 + 32

	// ContractRootOffset is the offset at which the sector Merkle
	// roots of the contract are stored.
	ContractRootOffset = 4096

	// ContractStackOffset is the offset at which the Merkle "stack" of the
	// sector Merkle roots is stored.
	ContractStackOffset = ContractRootOffset - (2048 + 8)

	// ContractVersion is the current version of the contract file format. It is
	// incremented after each change to the format.
	ContractVersion uint8 = 2
)

// ContractHeader contains the data encoded within the first
// ContractHeaderSize bytes of the contract file.
type ContractHeader struct {
	magic   string
	version uint8
	hostKey hostdb.HostPublicKey
	id      types.FileContractID
	key     crypto.SecretKey
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
	sectorRoots            merkle.Stack
	diskRoot               crypto.Hash
	f                      *os.File
}

// Close closes the contract file.
func (c *Contract) Close() error {
	// can ignore error here; nothing we can do about it, and it's not fatal
	_, _ = c.f.WriteAt(marshalStack(&c.sectorRoots), ContractStackOffset)
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
func (c *Contract) Key() proto.ContractKey {
	return proto.Ed25519ContractKey(c.header.key)
}

// AppendRoot appends a sector root to the contract, returning the new
// top-level Merkle root. The root should be written to durable storage.
func (c *Contract) AppendRoot(root crypto.Hash) (crypto.Hash, error) {
	if _, err := c.f.Seek(0, io.SeekEnd); err != nil {
		return crypto.Hash{}, errors.Wrap(err, "could not seek to end of contract file")
	}
	if _, err := c.f.Write(root[:]); err != nil {
		return crypto.Hash{}, errors.Wrap(err, "could not write new sector root")
	}
	// write must be durable
	if err := c.f.Sync(); err != nil {
		return crypto.Hash{}, errors.Wrap(err, "could not sync contract file")
	}
	c.sectorRoots.AppendLeafHash(root)
	c.diskRoot = c.sectorRoots.Root()
	return c.diskRoot, nil
}

// NumSectors returns the number of sector roots in the contract. It does not
// reflect any pending changes to the roots.
func (c *Contract) NumSectors() int {
	return c.sectorRoots.NumLeaves()
}

// SectorRoot returns the sector root at index i.
func (c *Contract) SectorRoot(i int) (crypto.Hash, error) {
	if _, err := c.f.Seek(ContractRootOffset+int64(i*crypto.HashSize), io.SeekStart); err != nil {
		return crypto.Hash{}, errors.Wrap(err, "could not seek to sector root")
	}
	var root crypto.Hash
	if _, err := io.ReadFull(c.f, root[:]); err != nil {
		return crypto.Hash{}, errors.Wrap(err, "could not read sector root")
	}
	return root, nil
}

// SyncWithHost synchronizes the local version of the contract with the host's
// version. This may involve modifying the sector roots and/or contract
// revision. SyncWithHost returns an error iff the contract has permanently
// desynchronized with the host and recovery is impossible.
func (c *Contract) SyncWithHost(hostRevision types.FileContractRevision, hostSignatures []types.TransactionSignature) error {
	renterRevision := c.Revision().Revision
	if hostRevision.NewRevisionNumber == renterRevision.NewRevisionNumber &&
		hostRevision.NewFileMerkleRoot == renterRevision.NewFileMerkleRoot &&
		c.diskRoot == renterRevision.NewFileMerkleRoot {
		// everything is synchronized
		return nil
	}
	if len(hostSignatures) != 2 {
		return errors.New("wrong number of host signatures")
	}

	// if the Merkle root is wrong, try to fix it.
	if hostRevision.NewFileMerkleRoot != c.diskRoot {
		// revert up to five roots
		orig := c.sectorRoots.NumLeaves()
		c.sectorRoots.Reset()
		if _, err := c.f.Seek(ContractRootOffset, io.SeekStart); err != nil {
			return errors.Wrap(err, "could not seek to contract sector roots")
		}
		if orig > 5 {
			r := bufio.NewReader(io.LimitReader(c.f, int64(orig-5)*crypto.HashSize))
			if _, err := c.sectorRoots.ReadFrom(r); err != nil {
				return errors.Wrap(err, "could not read sector roots")
			}
		}

		// re-apply each root, checking to see if the top-level root matches
		for c.sectorRoots.NumLeaves() != orig {
			// NOTE: the first iteration of the loop simply recalculates the
			// root without truncating. This accounts for the case where only
			// diskRoot is out of sync.
			if c.sectorRoots.Root() == hostRevision.NewFileMerkleRoot {
				// success!
				break
			}
			// append the next root
			if _, err := c.sectorRoots.ReadFrom(io.LimitReader(c.f, crypto.HashSize)); err != nil {
				return errors.Wrap(err, "could not read sector roots")
			}
		}
		if c.sectorRoots.Root() != hostRevision.NewFileMerkleRoot {
			// give up
			return proto.ErrDesynchronized
		}

		// truncate disk roots
		err := c.f.Truncate(ContractRootOffset + int64(c.sectorRoots.NumLeaves()*crypto.HashSize))
		if err != nil {
			return errors.Wrap(err, "could not repair sector roots")
		}
		c.diskRoot = hostRevision.NewFileMerkleRoot
	}

	// The Merkle roots should match now, so overwrite our revision with the
	// host's version. Since we signed the revision, this can't conceivably
	// hurt us.
	c.ContractRevision.Revision = hostRevision
	copy(c.ContractRevision.Signatures[:], hostSignatures)
	if _, err := c.f.WriteAt(marshalRevision(c.ContractRevision), ContractHeaderSize); err != nil {
		return errors.Wrap(err, "could not write contract revision")
	}
	return nil
}

func marshalHeader(rev proto.ContractRevision, key crypto.SecretKey) []byte {
	buf := bytes.NewBuffer(make([]byte, 0, ContractHeaderSize))
	buf.WriteString(ContractMagic)
	buf.WriteByte(ContractVersion)
	hpk := rev.HostKey().Ed25519()
	buf.Write(hpk[:])
	buf.Write(rev.Revision.ParentID[:])
	buf.Write(key[:32])
	return buf.Bytes()
}

func unmarshalHeader(b []byte) (h ContractHeader) {
	buf := bytes.NewBuffer(b)
	h.magic = string(buf.Next(len(ContractMagic)))
	h.version, _ = buf.ReadByte()
	var hpk crypto.PublicKey
	copy(hpk[:], buf.Next(32))
	h.hostKey = hostdb.HostPublicKey(types.Ed25519PublicKey(hpk).String())
	copy(h.id[:], buf.Next(32))
	copy(h.key[:], ed25519.NewKeyFromSeed(buf.Next(32)))
	return h
}

func marshalRevision(rev proto.ContractRevision) []byte {
	var buf bytes.Buffer
	buf.Grow(2048)
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

func marshalStack(stack *merkle.Stack) []byte {
	var buf bytes.Buffer
	stack.MarshalSia(&buf)
	return buf.Bytes()
}

func unmarshalStack(b []byte, stack *merkle.Stack) error {
	return stack.UnmarshalSia(bytes.NewReader(b))
}

// SaveContract creates a new contract file using the provided contract. The
// contract file will not contain any sector Merkle roots.
func SaveContract(contract proto.ContractRevision, key crypto.SecretKey, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return errors.Wrap(err, "could not create contract file")
	}
	defer f.Close()
	buf := make([]byte, ContractRootOffset)
	copy(buf, marshalHeader(contract, key))
	copy(buf[ContractHeaderSize:], marshalRevision(contract))
	if _, err := f.Write(buf); err != nil {
		return errors.Wrap(err, "could not write contract header and revision")
	} else if err := f.Sync(); err != nil {
		return errors.Wrap(err, "could not sync contract file")
	}
	return nil
}

// SaveRenewedContract creates a new contract file using the provided contract
// and the sector Merkle roots of the old contract.
func SaveRenewedContract(oldContract *Contract, newContract proto.ContractRevision, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return errors.Wrap(err, "could not create contract file")
	}
	defer f.Close()

	// write header+revision+stack
	if _, err := f.Write(marshalHeader(newContract, oldContract.header.key)); err != nil {
		return errors.Wrap(err, "could not write contract header")
	} else if _, err := f.WriteAt(marshalRevision(newContract), ContractHeaderSize); err != nil {
		return errors.Wrap(err, "could not write contract revision")
	} else if _, err := f.WriteAt(marshalStack(&oldContract.sectorRoots), ContractStackOffset); err != nil {
		return errors.Wrap(err, "could not write contract Merkle root stack")
	}

	// copy sector roots
	f.Seek(ContractRootOffset, io.SeekStart)
	oldContract.f.Seek(ContractRootOffset, io.SeekStart)
	if _, err := io.Copy(f, oldContract.f); err != nil {
		return errors.Wrap(err, "could not copy sector roots")
	} else if err := f.Sync(); err != nil {
		return errors.Wrap(err, "could not sync contract file")
	}

	return nil
}

// LoadContract loads a contract file, including all of its sector Merkle
// roots, into memory.
func LoadContract(filename string) (*Contract, error) {
	f, err := os.OpenFile(filename, os.O_RDWR, 0)
	if err != nil {
		return nil, errors.Wrap(err, "could not open contract file")
	}
	stat, err := f.Stat()
	if err != nil {
		return nil, errors.Wrap(err, "could not stat contract file")
	}
	if stat.Size() < ContractRootOffset {
		return nil, errors.New("contract file has invalid header")
	}
	numSectors := (stat.Size() - ContractRootOffset) / crypto.HashSize
	if stat.Size() != ContractRootOffset+numSectors*crypto.HashSize {
		// truncate to nearest sector
		if err = f.Truncate(ContractRootOffset + numSectors*crypto.HashSize); err != nil {
			return nil, errors.Wrap(err, "could not repair contract")
		}
	}

	// read header+revision+stack
	b := make([]byte, ContractRootOffset)
	if _, err := io.ReadFull(f, b); err != nil {
		return nil, errors.Wrap(err, "could not read contract metadata")
	}
	// decode header
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
	// decode stack
	var stack merkle.Stack
	err = unmarshalStack(b[ContractStackOffset:], &stack)
	if err != nil {
		return nil, errors.Wrap(err, "could not read Merkle stack")
	} else if stack.Root() != rev.Revision.NewFileMerkleRoot {
		// the stack is corrupted or outdated. Rebuild it from scratch using
		// the full set of roots.
		stack.Reset()
		if _, err := stack.ReadFrom(bufio.NewReader(f)); err != nil {
			return nil, errors.Wrap(err, "could not read sector roots")
		}
	}

	return &Contract{
		ContractRevision: rev,
		header:           header,
		sectorRoots:      stack,
		diskRoot:         stack.Root(),
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
	b := make([]byte, ContractStackOffset)
	if _, err := f.ReadAt(b, ContractHeaderSize); err != nil {
		return proto.ContractRevision{}, errors.Wrap(err, "could not read revision")
	}
	var rev proto.ContractRevision
	err = unmarshalRevision(b, &rev)
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
