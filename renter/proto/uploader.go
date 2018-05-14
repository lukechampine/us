package proto

import (
	"net"
	"time"

	"github.com/NebulousLabs/Sia/crypto"
	"github.com/NebulousLabs/Sia/encoding"
	"github.com/NebulousLabs/Sia/modules"
	"github.com/NebulousLabs/Sia/types"
	"github.com/lukechampine/us/hostdb"
	"github.com/pkg/errors"
)

// An Uploader uploads sectors by calling the revise RPC on a host. It updates
// the underlying file contract after each iteration of the upload protocol.
type Uploader struct {
	conn net.Conn
	host hostdb.ScannedHost

	height   types.BlockHeight
	contract ContractEditor
}

// HostKey returns the public key of the host being uploaded to.
func (u *Uploader) HostKey() hostdb.HostPublicKey {
	return u.host.PublicKey
}

// Close cleanly terminates the revision loop with the host and closes the
// connection.
func (u *Uploader) Close() error {
	return terminateRPC(u.conn, u.host)
}

// Upload negotiates a revision that adds a sector to a file contract, and
// revises the underlying contract to pay the host appropriately. Calls to
// Upload must be serialized.
func (u *Uploader) Upload(data *[SectorSize]byte) (crypto.Hash, error) {
	root, err := u.upload(data)
	if isHostDisconnect(err) {
		// try reconnecting
		u.conn.Close()
		u.conn, err = initiateRPC(u.host.NetAddress, modules.RPCReviseContract, u.contract)
		if err != nil {
			return crypto.Hash{}, err
		}
		root, err = u.upload(data)
	}
	return root, err
}

func (u *Uploader) upload(data *[SectorSize]byte) (crypto.Hash, error) {
	// allot 10 minutes for this exchange; sufficient to transfer 4 MB over 50 kbps
	extendDeadline(u.conn, modules.NegotiateFileContractRevisionTime)
	defer extendDeadline(u.conn, time.Hour) // reset deadline

	if len(data) != SectorSize {
		return crypto.Hash{}, errors.New("must upload exactly one sector")
	}

	// initiate revision, updating host settings
	if err := startRevision(u.conn, &u.host); err != nil {
		return crypto.Hash{}, err
	}

	// calculate price
	// TODO: height is never updated, so we'll wind up overpaying on long-running uploads
	txn := u.contract.Transaction()
	storageDuration := txn.CurrentRevision().NewWindowEnd - u.height
	storageDuration += 12 // hosts may not be fully synced; allow 2 hours of leeway
	blockBytes := types.NewCurrency64(SectorSize * uint64(storageDuration))
	sectorStoragePrice := u.host.StoragePrice.Mul(blockBytes)
	sectorBandwidthPrice := u.host.UploadBandwidthPrice.Mul64(SectorSize)
	sectorPrice := sectorStoragePrice.Add(sectorBandwidthPrice)
	if txn.RenterFunds().Cmp(sectorPrice) < 0 {
		return crypto.Hash{}, errors.Errorf("contract has insufficient funds to support upload: needed %v, have %v", sectorPrice, txn.RenterFunds())
	}
	sectorCollateral := u.host.Collateral.Mul(blockBytes)
	// hosts tend to be picky about collateral, so shave off 10%
	sectorCollateral = sectorCollateral.MulFloat(0.90)
	if txn.CurrentRevision().NewMissedProofOutputs[1].Value.Cmp(sectorCollateral) < 0 {
		return crypto.Hash{}, errors.New("contract has insufficient collateral to support upload")
	}

	// send actions
	actions := actionSet{{
		Type:        modules.ActionInsert,
		SectorIndex: uint64(u.contract.NumSectors()),
		Data:        data[:],
	}}
	if err := encoding.WriteInt(u.conn, actions.MarshalSiaSize()); err != nil {
		return crypto.Hash{}, errors.Wrap(err, "could not send revision action")
	} else if err := actions.MarshalSia(u.conn); err != nil {
		return crypto.Hash{}, errors.Wrap(err, "could not send revision action")
	}

	// calculate the new Merkle root and revision
	sectorRoot := SectorMerkleRoot(data)
	merkleRoot, err := u.contract.AppendRoot(sectorRoot)
	if err != nil {
		return crypto.Hash{}, errors.Wrap(err, "could not calculate new Merkle root")
	}
	rev := newUploadRevision(txn.CurrentRevision(), merkleRoot, sectorPrice, sectorCollateral)

	// update contract revision
	err = u.contract.Revise(rev)
	if err != nil {
		return crypto.Hash{}, errors.Wrap(err, "could not update contract revision")
	}

	// send revision to host and exchange signatures
	_, err = negotiateRevision(u.conn, rev, txn.RenterKey)
	if err != nil {
		u.conn.Close()
		if err == modules.ErrStopResponse {
			// if host gracefully closed, close our side too and suppress the
			// error. The next call to Upload will return an error that
			// satisfies IsHostDisconnect.
			return sectorRoot, nil
		}
		// host rejected revision; revert any changes to the contract
		oldTxn := txn.Transaction
		revertErr := u.contract.SyncWithHost(oldTxn.FileContractRevisions[0], oldTxn.TransactionSignatures)
		if revertErr != nil {
			return crypto.Hash{}, errors.Errorf("failed to revert contract after revision error: %v (revision error was: %v)", revertErr, err)
		}
		return crypto.Hash{}, err
	}

	return sectorRoot, nil
}

// NewUploader initiates the contract revision process with a host, and returns
// an Uploader.
func NewUploader(host hostdb.ScannedHost, contract ContractEditor, currentHeight types.BlockHeight) (*Uploader, error) {
	// check that contract has enough value to support an upload
	sectorPrice := host.UploadBandwidthPrice.Mul64(SectorSize)
	if contract.Transaction().RenterFunds().Cmp(sectorPrice) < 0 {
		return nil, errors.New("contract has insufficient funds to support upload")
	}
	conn, err := initiateRPC(host.NetAddress, modules.RPCReviseContract, contract)
	if err != nil {
		return nil, err
	}
	return &Uploader{
		host:     host,
		height:   currentHeight,
		contract: contract,
		conn:     conn,
	}, nil
}
