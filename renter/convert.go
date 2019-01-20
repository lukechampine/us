package renter

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
	"lukechampine.com/us/renter/proto"
)

// ConvertContractV1V2 converts a v1 contract to a v2 contract. The operation is
// atomic: if conversion fails, the v1 contract file will be unchanged.
func ConvertContractV1V2(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return errors.Wrap(err, "could not open contract file")
	}
	defer f.Close()

	// read header+revision+stack
	b := make([]byte, ContractRootOffset)
	if _, err := io.ReadFull(f, b); err != nil {
		return errors.Wrap(err, "could not read contract metadata")
	}
	// decode and validate header
	var h ContractHeader
	buf := bytes.NewBuffer(b[:ContractHeaderSize])
	if string(buf.Next(len(ContractMagic))) != ContractMagic {
		return errors.New("wrong magic bytes")
	}
	if version, _ := buf.ReadByte(); version != 1 {
		return errors.Errorf("expected version 1, got %v", version)
	}
	copy(h.id[:], buf.Next(32))
	copy(h.key[:], buf.Next(64))

	// decode revision
	var rev proto.ContractRevision
	buf = bytes.NewBuffer(b[ContractHeaderSize:])
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

	buf = bytes.NewBuffer(make([]byte, 0, ContractHeaderSize))
	buf.WriteString(ContractMagic)
	buf.WriteByte(2) // version
	hpk := rev.HostKey().Ed25519()
	buf.Write(hpk[:])
	buf.Write(h.id[:])
	buf.Write(h.key[:32])
	if _, err := buf.WriteTo(out); err != nil {
		return errors.Wrap(err, "could not write header")
	}

	// copy everything else directly
	if _, err := f.Seek(ContractHeaderSize, io.SeekStart); err != nil {
		return err
	} else if _, err := out.Seek(ContractHeaderSize, io.SeekStart); err != nil {
		return err
	}
	if _, err := io.Copy(out, f); err != nil {
		return errors.Wrap(err, "could not copy contract data")
	} else if err := out.Sync(); err != nil {
		return errors.Wrap(err, "could not sync new contract file")
	}
	// atomically replace the old contract
	if err := os.Rename(out.Name(), filename); err != nil {
		return errors.Wrap(err, "could not overwrite old contract")
	}
	return nil
}
