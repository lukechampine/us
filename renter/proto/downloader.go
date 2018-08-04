package proto

import (
	"io"
	"net"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/encoding"
	"gitlab.com/NebulousLabs/Sia/modules"
	"lukechampine.com/us/hostdb"
)

// A Downloader retrieves sectors by calling the download RPC on a host. It
// updates the corresponding contract after each iteration of the download
// protocol.
type Downloader struct {
	host     hostdb.ScannedHost
	contract ContractEditor
	conn     net.Conn
	buf      [24]byte // sufficient to read three length-prefixes
}

// HostKey returns the public key of the host being downloaded from.
func (d *Downloader) HostKey() hostdb.HostPublicKey {
	return d.host.PublicKey
}

// Close cleanly terminates the download loop with the host and closes the
// connection.
func (d *Downloader) Close() error {
	return terminateRPC(d.conn, d.host)
}

// Sector retrieves the sector with the specified Merkle root, and revises the
// underlying contract to pay the host appropriately. The sector data is
// written to dst. Sector verifies the integrity of the retrieved data by
// comparing its computed Merkle root to root.
func (d *Downloader) Sector(dst *[SectorSize]byte, root crypto.Hash) error {
	if err := d.PartialSector(dst[:], root, 0); err != nil {
		return err
	} else if SectorMerkleRoot(dst) != root {
		return errors.New("host sent invalid sector data")
	}
	return nil
}

// PartialSector retrieves the slice of sector data uniquely identified by
// root, offset, and len(dst), and revises the underlying contract to pay the
// host proportionally to the data retrieved. The data is written to dst.
//
// Unlike Sector, the integrity of the data cannot be verified by computing
// its Merkle root. Callers must implement a different means of integrity-
// checking, such as comparing against a known checksum.
func (d *Downloader) PartialSector(dst []byte, root crypto.Hash, offset uint32) error {
	err := d.partialSector(dst, root, offset)
	if isHostDisconnect(err) {
		// try reconnecting
		d.conn.Close()
		d.conn, err = initiateRPC(d.host.NetAddress, modules.RPCDownload, d.contract)
		if err != nil {
			return err
		}
		err = d.partialSector(dst, root, offset)
	}
	return err
}

func (d *Downloader) partialSector(dst []byte, root crypto.Hash, offset uint32) error {
	extendDeadline(d.conn, modules.NegotiateDownloadTime)
	defer extendDeadline(d.conn, time.Hour) // reset deadline when finished

	// sanity check for offset and length
	if uint64(offset)+uint64(len(dst)) > SectorSize {
		return errors.New("invalid sector range")
	}

	// initiate download, updating host settings
	if err := startRevision(d.conn, &d.host); err != nil {
		return err
	}

	// calculate price
	sectorPrice := d.host.DownloadBandwidthPrice.Mul64(uint64(len(dst)))
	contract := d.contract.Revision()
	if contract.RenterFunds().Cmp(sectorPrice) < 0 {
		return errors.New("contract has insufficient funds to support download")
	}

	// send download action
	err := encoding.WriteObject(d.conn, []modules.DownloadAction{{
		MerkleRoot: root,
		Offset:     uint64(offset),
		Length:     uint64(len(dst)),
	}})
	if err != nil {
		return errors.Wrap(err, "could not send revision action")
	}

	// create the download revision
	rev := newDownloadRevision(contract.Revision, sectorPrice)

	// send the revision to the host for approval
	txnSignatures, err := negotiateRevision(d.conn, rev, contract.RenterKey)
	if err == modules.ErrStopResponse {
		// if host gracefully closed, ignore the error. The next download
		// attempt will return an error that satisfies IsHostDisconnect.
	} else if err != nil {
		d.conn.Close()
		return err
	}

	// update contract revision
	err = d.contract.SyncWithHost(rev, txnSignatures)
	if err != nil {
		return errors.Wrap(err, "could not update contract transaction")
	}

	// read payload length prefixes
	if _, err := io.ReadFull(d.conn, d.buf[:24]); err != nil {
		return err
	}
	totalSize := encoding.DecUint64(d.buf[0:8])
	numSectors := encoding.DecUint64(d.buf[8:16])
	payloadSize := encoding.DecUint64(d.buf[16:24])
	if totalSize > SectorSize+16 {
		d.conn.Close()
		return errors.New("reported payload size is larger than SectorSize")
	} else if numSectors != 1 {
		d.conn.Close()
		return errors.New("wrong number of sectors")
	} else if payloadSize > SectorSize {
		d.conn.Close()
		return errors.New("reported sector data is larger than SectorSize")
	}

	// read sector data, completing one iteration of the download loop
	_, err = io.ReadFull(d.conn, dst)
	if err != nil {
		d.conn.Close()
		return err
	}
	return nil
}

// NewDownloader initiates the download request loop with a host, and returns a
// Downloader.
func NewDownloader(host hostdb.ScannedHost, contract ContractEditor) (*Downloader, error) {
	conn, err := initiateRPC(host.NetAddress, modules.RPCDownload, contract)
	if err != nil {
		return nil, err
	}
	return &Downloader{
		contract: contract,
		host:     host,
		conn:     conn,
	}, nil
}
