package renter

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/ed25519"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter/proto"
)

const (
	v1ContractHeaderSize = 11 + 1 + 32 + 64
	v1ContractRootOffset = 4096

	v2ContractHeaderSize = 11 + 1 + 32 + 32 + 32
	v2ContractRootOffset = 4096

	v3ContractHeaderSize = 11 + 1 + 32 + 32 + 32

	v4ContractSize = 11 + 1 + 32 + 32 + 32
)

// ConvertContract converts a contract file to the latest version of the
// contract format. The operation is atomic: if conversion fails, the old
// contract file will be unchanged.
func ConvertContract(filename string) error {
	// determine contract version
	f, err := os.Open(filename)
	if err != nil {
		return errors.Wrap(err, "could not open contract file")
	}
	b := make([]byte, len(ContractMagic)+1)
	_, err = io.ReadFull(f, b)
	f.Close()
	if err != nil {
		return errors.Wrap(err, "could not read contract metadata")
	}
	if string(b[:len(ContractMagic)]) != ContractMagic {
		return errors.New("not a contract file")
	}
	version := b[len(ContractMagic)]

	switch version {
	case 1:
		if err := convertContractV1V2(filename); err != nil {
			return err
		}
		fallthrough
	case 2:
		if err := convertContractV2V3(filename); err != nil {
			return err
		}
		fallthrough
	case 3:
		if err := convertContractV3V4(filename); err != nil {
			return err
		}
		fallthrough
	case 4:
		return nil
	default:
		return errors.Errorf("unrecognized contract version %v", version)
	}
}

func convertContractV1V2(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return errors.Wrap(err, "could not open contract file")
	}
	defer f.Close()

	// read header+revision+stack
	b := make([]byte, v1ContractRootOffset)
	if _, err := io.ReadFull(f, b); err != nil {
		return errors.Wrap(err, "could not read contract metadata")
	}
	// decode and validate header
	var h struct {
		id  types.FileContractID
		key ed25519.PrivateKey
	}
	buf := bytes.NewBuffer(b[:v1ContractHeaderSize])
	if string(buf.Next(len(ContractMagic))) != ContractMagic {
		return errors.New("wrong magic bytes")
	}
	if version, _ := buf.ReadByte(); version != 1 {
		return errors.Errorf("expected version 1, got %v", version)
	}
	copy(h.id[:], buf.Next(32))
	copy(h.key[:], buf.Next(64))

	// decode revision
	var rev struct {
		Revision   types.FileContractRevision
		Signatures [2]types.TransactionSignature
	}
	buf = bytes.NewBuffer(b[v1ContractHeaderSize:])
	if err := rev.Revision.UnmarshalSia(buf); err != nil {
		return err
	} else if err := rev.Signatures[0].UnmarshalSia(buf); err != nil {
		return err
	} else if err := rev.Signatures[1].UnmarshalSia(buf); err != nil {
		return err
	}

	// write the converted contract to disk
	out, err := ioutil.TempFile("", "")
	if err != nil {
		return errors.Wrap(err, "could not create temp file to hold new contract")
	}
	defer out.Close()

	buf = bytes.NewBuffer(make([]byte, 0, v2ContractHeaderSize))
	buf.WriteString(ContractMagic)
	buf.WriteByte(2) // version
	hpk := hostdb.HostKeyFromSiaPublicKey(rev.Revision.UnlockConditions.PublicKeys[1])
	buf.Write(hpk.Ed25519())
	buf.Write(h.id[:])
	buf.Write(h.key[:32])
	if _, err := buf.WriteTo(out); err != nil {
		return errors.Wrap(err, "could not write header")
	}

	// copy everything else directly
	if _, err := f.Seek(v1ContractHeaderSize, io.SeekStart); err != nil {
		return err
	} else if _, err := out.Seek(v2ContractHeaderSize, io.SeekStart); err != nil {
		return err
	}
	if _, err := io.Copy(out, f); err != nil {
		return errors.Wrap(err, "could not copy contract data")
	} else if err := out.Sync(); err != nil {
		return errors.Wrap(err, "could not sync new contract file")
	}
	// atomically replace the old contract
	out.Close()
	if err := os.Rename(out.Name(), filename); err != nil {
		return errors.Wrap(err, "could not overwrite old contract")
	}
	return nil
}

func convertContractV2V3(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return errors.Wrap(err, "could not open contract file")
	}
	defer f.Close()

	// read header+revision+stack
	b := make([]byte, v2ContractRootOffset)
	if _, err := io.ReadFull(f, b); err != nil {
		return errors.Wrap(err, "could not read contract metadata")
	}
	// decode and validate header
	var h struct {
		hpk hostdb.HostPublicKey
		id  types.FileContractID
		key ed25519.PrivateKey
	}
	buf := bytes.NewBuffer(b[:v2ContractHeaderSize])
	if string(buf.Next(len(ContractMagic))) != ContractMagic {
		return errors.New("wrong magic bytes")
	}
	if version, _ := buf.ReadByte(); version != 2 {
		return errors.Errorf("expected version 2, got %v", version)
	}
	h.hpk = hostdb.HostKeyFromPublicKey(buf.Next(32))
	copy(h.id[:], buf.Next(32))
	h.key = ed25519.NewKeyFromSeed(buf.Next(32))

	// decode revision
	var rev proto.ContractRevision
	buf = bytes.NewBuffer(b[v2ContractHeaderSize:])
	if err := rev.Revision.UnmarshalSia(buf); err != nil {
		return err
	} else if err := rev.Signatures[0].UnmarshalSia(buf); err != nil {
		return err
	} else if err := rev.Signatures[1].UnmarshalSia(buf); err != nil {
		return err
	}

	// write the converted contract to disk
	out, err := ioutil.TempFile("", "")
	if err != nil {
		return errors.Wrap(err, "could not create temp file to hold new contract")
	}
	defer out.Close()

	b = make([]byte, ContractSize)
	buf = bytes.NewBuffer(b[:0])
	buf.WriteString(ContractMagic)
	buf.WriteByte(3) // version
	buf.Write(h.hpk.Ed25519())
	buf.Write(h.id[:])
	buf.Write(h.key[:32])
	rev.Revision.MarshalSia(buf)
	rev.Signatures[0].MarshalSia(buf)
	rev.Signatures[1].MarshalSia(buf)
	if _, err := out.Write(b); err != nil {
		return errors.Wrap(err, "could not write header")
	} else if err := out.Sync(); err != nil {
		return errors.Wrap(err, "could not sync new contract file")
	}
	// atomically replace the old contract
	out.Close()
	if err := os.Rename(out.Name(), filename); err != nil {
		return errors.Wrap(err, "could not overwrite old contract")
	}
	return nil
}

func convertContractV3V4(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return errors.Wrap(err, "could not open contract file")
	}
	defer f.Close()

	// read header
	b := make([]byte, v3ContractHeaderSize)
	if _, err := io.ReadFull(f, b); err != nil {
		return errors.Wrap(err, "could not read contract metadata")
	}
	// decode and validate header
	var h struct {
		hpk hostdb.HostPublicKey
		id  types.FileContractID
		key ed25519.PrivateKey
	}
	buf := bytes.NewBuffer(b)
	if string(buf.Next(len(ContractMagic))) != ContractMagic {
		return errors.New("wrong magic bytes")
	}
	if version, _ := buf.ReadByte(); version != 2 {
		return errors.Errorf("expected version 2, got %v", version)
	}
	h.hpk = hostdb.HostKeyFromPublicKey(buf.Next(32))
	copy(h.id[:], buf.Next(32))
	h.key = ed25519.NewKeyFromSeed(buf.Next(32))

	// write the converted contract to disk
	out, err := ioutil.TempFile("", "")
	if err != nil {
		return errors.Wrap(err, "could not create temp file to hold new contract")
	}
	defer out.Close()

	b = make([]byte, v4ContractSize)
	buf = bytes.NewBuffer(b[:0])
	buf.WriteString(ContractMagic)
	buf.WriteByte(4) // version
	buf.Write(h.hpk.Ed25519())
	buf.Write(h.id[:])
	buf.Write(h.key[:32])
	if _, err := out.Write(b); err != nil {
		return errors.Wrap(err, "could not write header")
	} else if err := out.Sync(); err != nil {
		return errors.Wrap(err, "could not sync new contract file")
	}
	// atomically replace the old contract
	out.Close()
	if err := os.Rename(out.Name(), filename); err != nil {
		return errors.Wrap(err, "could not overwrite old contract")
	}
	return nil
}
