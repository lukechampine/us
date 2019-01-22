package proto

import (
	"net"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/encoding"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renterhost"
)

// An Uploader uploads sectors by calling the revise RPC on a host. It updates
// the underlying file contract after each iteration of the upload protocol.
type Uploader struct {
	conn net.Conn
	host hostdb.ScannedHost

	height   types.BlockHeight
	contract ContractEditor
	// stats
	dialStats DialStats
	lastStats UploadStats
}

// HostKey returns the public key of the host being uploaded to.
func (u *Uploader) HostKey() hostdb.HostPublicKey {
	return u.host.PublicKey
}

// DialStats returns the metrics of the initial connection to the host.
func (u *Uploader) DialStats() DialStats {
	return u.dialStats
}

// LastUploadStats returns the metrics of the most recent successful upload.
func (u *Uploader) LastUploadStats() UploadStats {
	return u.lastStats
}

// Close cleanly terminates the revision loop with the host and closes the
// connection.
func (u *Uploader) Close() error {
	return terminateRPC(u.conn, u.host)
}

// Upload negotiates a revision that adds a sector to a file contract, and
// revises the underlying contract to pay the host appropriately.
func (u *Uploader) Upload(data *[renterhost.SectorSize]byte) (crypto.Hash, error) {
	root, err := u.upload(data)
	if isHostDisconnect(err) {
		// try reconnecting
		u.conn.Close()
		u.conn, _, err = initiateRPC(u.host.NetAddress, modules.RPCReviseContract, u.contract)
		if err != nil {
			return crypto.Hash{}, err
		}
		root, err = u.upload(data)
	}
	return root, err
}

func (u *Uploader) upload(data *[renterhost.SectorSize]byte) (crypto.Hash, error) {
	// allot 10 minutes for this exchange; sufficient to transfer 4 MB over 50 kbps
	extendDeadline(u.conn, modules.NegotiateFileContractRevisionTime)
	defer extendDeadline(u.conn, time.Hour) // reset deadline

	// initiate revision, updating host settings
	if err := startRevision(u.conn, &u.host); err != nil {
		return crypto.Hash{}, err
	}

	// calculate price
	// TODO: height is never updated, so we'll wind up overpaying on long-running uploads
	currentRev := u.contract.Revision()
	storageDuration := currentRev.Revision.NewWindowEnd - u.height
	storageDuration += 12 // hosts may not be fully synced; allow 2 hours of leeway
	blockBytes := types.NewCurrency64(renterhost.SectorSize * uint64(storageDuration))
	sectorStoragePrice := u.host.StoragePrice.Mul(blockBytes)
	sectorBandwidthPrice := u.host.UploadBandwidthPrice.Mul64(renterhost.SectorSize)
	sectorPrice := sectorStoragePrice.Add(sectorBandwidthPrice)
	if currentRev.RenterFunds().Cmp(sectorPrice) < 0 {
		return crypto.Hash{}, errors.Errorf("contract has insufficient funds to support upload: needed %v, have %v", sectorPrice, currentRev.RenterFunds())
	}
	sectorCollateral := u.host.Collateral.Mul(blockBytes)
	// hosts tend to be picky about collateral, so shave off 15%
	sectorCollateral = sectorCollateral.MulFloat(0.85)
	if currentRev.Revision.NewMissedProofOutputs[1].Value.Cmp(sectorCollateral) < 0 {
		return crypto.Hash{}, errors.New("contract has insufficient collateral to support upload")
	}

	// send sector data to host while concurrently calculating its Merkle root
	// and writing it to disk
	errChan := make(chan error)
	var sectorRoot, merkleRoot crypto.Hash
	go func() {
		sectorRoot = merkle.SectorRoot(data)
		var err error
		merkleRoot, err = u.contract.AppendRoot(sectorRoot)
		errChan <- err
	}()

	// send actions
	xferStart := time.Now()
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
	xferEnd := time.Now()
	if err := <-errChan; err != nil {
		return crypto.Hash{}, errors.Wrap(err, "could not calculate new Merkle root")
	}
	// create the upload revision and sign it
	rev := newUploadRevision(currentRev, merkleRoot, sectorPrice, sectorCollateral)
	renterSig := revisionSignature(rev, u.contract.Key())

	// send revision to host and exchange signatures
	protoStart := time.Now()
	txnSignatures, err := negotiateRevision(u.conn, rev, renterSig)
	protoEnd := time.Now()
	if err == modules.ErrStopResponse {
		// if host gracefully closed, close our side too and suppress the
		// error. The next call to Upload will return an error that
		// satisfies IsHostDisconnect.
		u.conn.Close()
		return sectorRoot, nil
	} else if err != nil {
		// the host rejected revision for some reason. It may also have lost
		// power. In the latter case, the host may have accepted the revision.
		// Since we cannot be sure, don't revert the AppendRoot yet; that will
		// be handled by SyncWithHost the next time we connect to the host.
		u.conn.Close()
		return crypto.Hash{}, err
	}

	// update contract revision
	err = u.contract.SyncWithHost(rev, txnSignatures)
	if err != nil {
		return crypto.Hash{}, errors.Wrap(err, "could not update contract transaction")
	}

	u.lastStats = UploadStats{
		Bytes:         renterhost.SectorSize,
		Cost:          sectorPrice,
		Collateral:    sectorCollateral,
		ProtocolStart: protoStart,
		ProtocolEnd:   protoEnd,
		TransferStart: xferStart,
		TransferEnd:   xferEnd,
	}
	return sectorRoot, nil
}

// NewUploader initiates the contract revision process with a host, and returns
// an Uploader.
func NewUploader(hostIP modules.NetAddress, contract ContractEditor, currentHeight types.BlockHeight) (*Uploader, error) {
	if currentHeight >= contract.Revision().Revision.NewWindowEnd {
		return nil, errors.New("contract has expired")
	}
	conn, stats, err := initiateRPC(hostIP, modules.RPCReviseContract, contract)
	if err != nil {
		return nil, err
	}
	return &Uploader{
		host: hostdb.ScannedHost{
			HostSettings: hostdb.HostSettings{
				NetAddress: hostIP,
			},
			PublicKey: contract.Revision().HostKey(),
		},
		height:    currentHeight,
		contract:  contract,
		conn:      conn,
		dialStats: stats,
	}, nil
}
