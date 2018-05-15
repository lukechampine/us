package renter

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"unsafe"

	"github.com/NebulousLabs/Sia/crypto"
	"github.com/NebulousLabs/Sia/types"
	"github.com/pkg/errors"

	"github.com/lukechampine/us/hostdb"
	"github.com/lukechampine/us/renter/proto"
)

const (
	// ContractMagic is the magic string that identifies contract files.
	ContractMagic = "us-contract"

	// ContractHeaderSize is the size in bytes of the contract file header.
	ContractHeaderSize = 11 + 1 + 32 + 64

	// ContractRootOffset is the offset at which the binary-encoded sector Merkle
	// roots of the contract are stored. An offset of 4096 bytes was chosen
	// because it should hold any reasonably-sized transaction and is also the
	// size of a block on most filesystems (and, increasingly, on the underlying
	// hardware).
	ContractRootOffset = 4096

	// ContractArenaSize is the size in bytes of the contract file "arena," which
	// contains the JSON-encoded contract transaction.
	ContractArenaSize = ContractRootOffset - ContractHeaderSize

	// ContractVersion is the current version of the contract file format. It is
	// incremented after each change to the format.
	ContractVersion uint8 = 1
)

// ContractHeader contains the data encoded within the first
// ContractHeaderSize bytes of the contract file.
type ContractHeader struct {
	magic   string
	version uint8
	id      types.FileContractID
	key     crypto.SecretKey
}

// Validate validates a ContractHeader, checking its magic bytes and version.
func (h *ContractHeader) Validate() error {
	if h.magic != ContractMagic {
		return errors.Errorf("wrong magic bytes (%q)", h.magic)
	}
	if h.version != ContractVersion {
		return errors.Errorf("wrong version (%d)", h.version)
	}
	return nil
}

// A Contract represents an open contract file. Contract files contain all the
// data necessary to revise a file contract.
type Contract struct {
	proto.ContractTransaction // for convenience
	header                    ContractHeader
	sectorRoots               []crypto.Hash
	diskRoot                  crypto.Hash
	f                         *os.File
}

// Close closes the contract file.
func (c *Contract) Close() error {
	if err := c.f.Sync(); err != nil {
		return err
	}
	return c.f.Close()
}

// Transaction returns the transaction containing the latest revision of
// the file contract.
func (c *Contract) Transaction() proto.ContractTransaction {
	return c.ContractTransaction
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
	c.sectorRoots = append(c.sectorRoots, root)
	c.diskRoot = proto.CachedMerkleRoot(c.sectorRoots)
	return c.diskRoot, nil
}

// Revise sets the latest revision of the file contract.
func (c *Contract) Revise(rev types.FileContractRevision) error {
	c.ContractTransaction.Transaction.FileContractRevisions[0] = rev
	if _, err := c.f.Seek(ContractHeaderSize, io.SeekStart); err != nil {
		return errors.Wrap(err, "could not seek to transaction")
	} else if err := writeContractTransaction(c.f, c.ContractTransaction.Transaction); err != nil {
		return err
	} else if err := c.f.Sync(); err != nil {
		return errors.Wrap(err, "could not sync contract file")
	}
	return nil
}

// NumSectors returns the number of sector roots in the contract. It does not
// reflect any pending changes to the roots.
func (c *Contract) NumSectors() int {
	return len(c.sectorRoots)
}

// SectorRoot returns the sector root at index i.
func (c *Contract) SectorRoot(i int) (crypto.Hash, error) {
	return c.sectorRoots[i], nil
}

// SyncWithHost synchronizes the local version of the contract with the host's
// version. This may involve modifying the sector roots and/or contract
// revision. SyncWithHost returns an error iff the contract has permanently
// desynchronized with the host and recovery is impossible.
func (c *Contract) SyncWithHost(hostRevision types.FileContractRevision, hostSignatures []types.TransactionSignature) error {
	renterRevision := c.Transaction().CurrentRevision()
	if hostRevision.NewRevisionNumber == renterRevision.NewRevisionNumber &&
		hostRevision.NewFileMerkleRoot == renterRevision.NewFileMerkleRoot &&
		c.diskRoot == renterRevision.NewFileMerkleRoot {
		// everything is synchronized
		return nil
	}

	if hostRevision.NewFileMerkleRoot != renterRevision.NewFileMerkleRoot || hostRevision.NewFileMerkleRoot != c.diskRoot {
		// try removing sector roots until top-level root matches the host
		var fixed bool
		for i := 0; i <= len(c.sectorRoots) && i < 5; i++ {
			// NOTE: the first iteration of the loop simply recalculates the
			// root without truncating. This accounts for the case where only
			// diskRoot is out of sync.
			truncatedRoots := c.sectorRoots[:len(c.sectorRoots)-i]
			if proto.CachedMerkleRoot(truncatedRoots) == hostRevision.NewFileMerkleRoot {
				// truncate disk roots
				err := c.f.Truncate(ContractRootOffset + int64(len(truncatedRoots)*crypto.HashSize))
				if err != nil {
					return errors.Wrap(err, "could not repair sector roots")
				}
				c.sectorRoots = truncatedRoots
				c.diskRoot = hostRevision.NewFileMerkleRoot
				fixed = true
				break
			}
		}
		if !fixed {
			return proto.ErrDesynchronized
		}
	}

	// The Merkle roots should match now, so overwrite our revision with the
	// host's version. Since we signed the revision, this can't conceivably
	// hurt us.
	c.ContractTransaction.Transaction.TransactionSignatures = hostSignatures
	err := c.Revise(hostRevision)
	if err != nil {
		return errors.Wrap(err, "could not update revision to match host's")
	}
	return nil
}

func writeContractHeader(w io.Writer, contract proto.ContractTransaction) error {
	header := make([]byte, ContractHeaderSize)
	n := copy(header, ContractMagic)
	header[n] = ContractVersion
	n++
	id := contract.ID()
	n += copy(header[n:], id[:])
	copy(header[n:], contract.RenterKey[:])
	_, err := w.Write(header)
	return err
}

func readContractHeader(r io.Reader) (ContractHeader, error) {
	b := make([]byte, ContractHeaderSize)
	if _, err := io.ReadFull(r, b); err != nil {
		return ContractHeader{}, errors.Wrap(err, "could not read contract header")
	}
	buf := bytes.NewBuffer(b)

	var header ContractHeader
	header.magic = string(buf.Next(len(ContractMagic)))
	header.version, _ = buf.ReadByte()
	copy(header.id[:], buf.Next(32))
	copy(header.key[:], buf.Next(64))
	return header, nil
}

func writeContractTransaction(w io.Writer, txn types.Transaction) error {
	arena := make([]byte, ContractArenaSize)
	err := json.NewEncoder(bytes.NewBuffer(arena[:0])).Encode(txn)
	if err != nil {
		return errors.Wrap(err, "could not encode contract transaction")
	}
	_, err = w.Write(arena)
	return err
}

func readContractTransaction(r io.Reader) (types.Transaction, error) {
	arena := make([]byte, ContractArenaSize)
	if _, err := io.ReadFull(r, arena); err != nil {
		return types.Transaction{}, errors.Wrap(err, "could not read contract transaction")
	}
	var txn types.Transaction
	err := json.NewDecoder(bytes.NewReader(arena)).Decode(&txn)
	if err != nil {
		return types.Transaction{}, errors.Wrap(err, "could not decode contract transaction")
	}
	return txn, nil
}

// SaveContract creates a new contract file using the provided contract. The
// contract file will not contain any sector Merkle roots.
func SaveContract(contract proto.ContractTransaction, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return errors.Wrap(err, "could not create contract file")
	}
	defer f.Close()
	if err := writeContractHeader(f, contract); err != nil {
		return errors.Wrap(err, "could not write contract header")
	} else if err := writeContractTransaction(f, contract.Transaction); err != nil {
		return errors.Wrap(err, "could not write contract transaction")
	} else if err := f.Sync(); err != nil {
		return errors.Wrap(err, "could not sync contract file")
	}
	return nil
}

// SaveRenewedContract creates a new contract file using the provided contract
// and the sector Merkle roots of the old contract.
func SaveRenewedContract(oldContract *Contract, newContract proto.ContractTransaction, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return errors.Wrap(err, "could not create contract file")
	}
	defer f.Close()

	// write header+transaction
	if err := writeContractHeader(f, newContract); err != nil {
		return errors.Wrap(err, "could not write contract header")
	} else if err := writeContractTransaction(f, newContract.Transaction); err != nil {
		return errors.Wrap(err, "could not write contract transaction")
	}

	// write sector roots
	roots := oldContract.sectorRoots
	rootsBytes := *(*[]byte)(unsafe.Pointer(&reflect.SliceHeader{
		Len:  len(roots),
		Cap:  len(roots),
		Data: (*reflect.SliceHeader)(unsafe.Pointer(&roots)).Data,
	}))
	if _, err := f.Write(rootsBytes); err != nil {
		return errors.Wrap(err, "could not write sector roots")
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

	// read header
	header, err := readContractHeader(f)
	if err != nil {
		return nil, err
	} else if err := header.Validate(); err != nil {
		return nil, errors.Wrap(err, "contract is invalid")
	}
	// read transaction
	// TODO: try to recover if txn is invalid?
	txn, err := readContractTransaction(f)
	if err != nil {
		return nil, err
	} else if ct := (proto.ContractTransaction{Transaction: txn}); !ct.IsValid() {
		return nil, errors.Wrap(err, "contract transaction is invalid")
	} else if ct.ID() != header.id {
		return nil, errors.New("contract transaction has wrong ID")
	}

	// read sector roots
	if _, err := f.Seek(ContractRootOffset, io.SeekStart); err != nil {
		return nil, errors.Wrap(err, "could not seek to contract sector roots")
	}
	rootsBytes := make([]byte, numSectors*crypto.HashSize)
	if _, err := io.ReadFull(f, rootsBytes); err != nil {
		return nil, errors.Wrap(err, "could not read sector roots")
	}
	roots := *(*[]crypto.Hash)(unsafe.Pointer(&reflect.SliceHeader{
		Len:  int(numSectors),
		Cap:  int(numSectors),
		Data: (*reflect.SliceHeader)(unsafe.Pointer(&rootsBytes)).Data,
	}))

	return &Contract{
		ContractTransaction: proto.ContractTransaction{
			Transaction: txn,
			RenterKey:   header.key,
		},
		header:      header,
		sectorRoots: roots,
		diskRoot:    proto.CachedMerkleRoot(roots),
		f:           f,
	}, nil
}

// ReadContractTransaction reads, decodes, and returns the ContractTransaction
// of a contract file. The ContractTransaction is not validated.
func ReadContractTransaction(filename string) (proto.ContractTransaction, error) {
	f, err := os.Open(filename)
	if err != nil {
		return proto.ContractTransaction{}, errors.Wrap(err, "could not open contract file")
	}
	defer f.Close()
	header, err := readContractHeader(f)
	if err != nil {
		return proto.ContractTransaction{}, errors.Wrap(err, "could not read header")
	}
	txn, err := readContractTransaction(f)
	if err != nil {
		return proto.ContractTransaction{}, errors.Wrap(err, "could not read transaction")
	}
	return proto.ContractTransaction{
		Transaction: txn,
		RenterKey:   header.key,
	}, nil
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
