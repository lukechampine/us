package proto

import (
	"encoding/json"
	"io"
	"net"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renterhost"
)

// ErrInvalidMerkleProof is returned by various RPCs when the host supplies an
// invalid Merkle proof.
var ErrInvalidMerkleProof = errors.New("host supplied invalid Merkle proof")

// A Session is an ongoing exchange of RPCs via the renter-host protocol.
type Session struct {
	sess    *renterhost.Session
	conn    net.Conn
	readBuf [renterhost.SectorSize]byte

	host     hostdb.ScannedHost
	height   types.BlockHeight
	contract ContractEditor

	// stats
	dialStats  DialStats
	lastDStats DownloadStats
	lastUStats UploadStats
}

// HostKey returns the public key of the host.
func (s *Session) HostKey() hostdb.HostPublicKey { return s.host.PublicKey }

// DialStats returns the metrics of the initial connection to the host.
func (s *Session) DialStats() DialStats { return s.dialStats }

// LastDownloadStats returns the metrics of the most recent successful
// download.
func (s *Session) LastDownloadStats() DownloadStats { return s.lastDStats }

// LastUploadStats returns the metrics of the most recent successful upload.
func (s *Session) LastUploadStats() UploadStats { return s.lastUStats }

func (s *Session) extendDeadline(d time.Duration) {
	_ = s.conn.SetDeadline(time.Now().Add(d))
}

// call is a helper method that writes a request and then reads a response.
func (s *Session) call(rpcID renterhost.Specifier, req, resp renterhost.ProtocolObject) error {
	if err := s.sess.WriteRequest(rpcID, req); err != nil {
		return err
	}
	// use a maxlen large enough for all RPCs except Read and Write (which don't
	// use call anyway)
	return s.sess.ReadResponse(resp, 4096)
}

// Lock calls the Lock RPC, locking the supplied contract and synchronizing its
// state with the host's most recent revision. Subsequent RPCs will modify the
// supplied contract.
func (s *Session) Lock(contract ContractEditor) error {
	req := &renterhost.RPCLockRequest{
		ContractID: contract.Revision().ID(),
		Signature:  s.sess.SignChallenge(contract.Key()),
		Timeout:    10e3, // 10 seconds
	}
	s.extendDeadline(15 * time.Second)
	var resp renterhost.RPCLockResponse
	if err := s.call(renterhost.RPCLockID, req, &resp); err != nil {
		return err
	}
	s.sess.SetChallenge(resp.NewChallenge)
	rev := ContractRevision{Revision: resp.Revision}
	copy(rev.Signatures[:], resp.Signatures)
	if err := contract.SetRevision(rev); err != nil {
		return err
	}
	if !resp.Acquired {
		return errors.New("contract is locked by another party")
	}
	s.contract = contract
	return nil
}

// Unlock calls the Unlock RPC, unlocking the currently-locked contract.
//
// It is typically not necessary to manually unlock a contract, as the host will
// automatically unlock any locked contracts when the connection closes.
func (s *Session) Unlock() error {
	if s.contract == nil {
		return errors.New("no contract locked")
	}
	s.extendDeadline(10 * time.Second)
	return s.sess.WriteRequest(renterhost.RPCUnlockID, nil)
}

// Settings calls the Settings RPC, returning the host's reported settings.
func (s *Session) Settings() (hostdb.HostSettings, error) {
	s.extendDeadline(10 * time.Second)
	var resp renterhost.RPCSettingsResponse
	if err := s.call(renterhost.RPCSettingsID, nil, &resp); err != nil {
		return hostdb.HostSettings{}, err
	} else if err := json.Unmarshal(resp.Settings, &s.host.HostSettings); err != nil {
		return hostdb.HostSettings{}, err
	}
	return s.host.HostSettings, nil
}

// SectorRoots calls the SectorRoots RPC, returning the requested range of
// sector Merkle roots of the currently-locked contract.
func (s *Session) SectorRoots(offset, n int) ([]crypto.Hash, error) {
	rev := s.contract.Revision().Revision
	totalSectors := int(rev.NewFileSize / renterhost.SectorSize)
	if offset < 0 || n < 0 || offset+n > totalSectors {
		return nil, errors.New("requested range is out-of-bounds")
	}

	// calculate price
	proofHashes := merkle.ProofSize(totalSectors, offset, offset+n)
	bandwidth := (proofHashes + n) * crypto.HashSize
	if bandwidth < renterhost.MinMessageSize {
		bandwidth = renterhost.MinMessageSize
	}
	bandwidthPrice := s.host.DownloadBandwidthPrice.Mul64(uint64(bandwidth))
	price := s.host.BaseRPCPrice.Add(bandwidthPrice)
	if rev.RenterFunds().Cmp(price) < 0 {
		return nil, errors.New("contract has insufficient funds to support sector roots download")
	}

	// construct new revision
	rev.NewRevisionNumber++
	newValid, newMissed := updateRevisionOutputs(&rev, price, types.ZeroCurrency)

	s.extendDeadline(60*time.Second + time.Duration(bandwidth)/time.Microsecond)
	req := &renterhost.RPCSectorRootsRequest{
		RootOffset: uint64(offset),
		NumRoots:   uint64(n),

		NewRevisionNumber:    rev.NewRevisionNumber,
		NewValidProofValues:  newValid,
		NewMissedProofValues: newMissed,
		Signature:            s.contract.Key().SignHash(crypto.HashObject(rev)),
	}
	var resp renterhost.RPCSectorRootsResponse
	if err := s.call(renterhost.RPCSectorRootsID, req, &resp); err != nil {
		return nil, err
	}
	sigs := s.contract.Revision().Signatures
	sigs[0].Signature = req.Signature
	sigs[1].Signature = resp.Signature
	if err := s.contract.SetRevision(ContractRevision{rev, sigs}); err != nil {
		return nil, err
	}
	if !merkle.VerifySectorRangeProof(resp.MerkleProof, resp.SectorRoots, offset, offset+n, totalSectors, rev.NewFileMerkleRoot) {
		return nil, ErrInvalidMerkleProof
	}
	return resp.SectorRoots, nil
}

// Read calls the Read RPC, writing the requested sections of sector data to w.
// Merkle proofs are always requested.
func (s *Session) Read(w io.Writer, sections []renterhost.RPCReadRequestSection) error {
	rev := s.contract.Revision().Revision

	// calculate price
	sectorAccesses := make(map[crypto.Hash]struct{})
	for _, sec := range sections {
		sectorAccesses[sec.MerkleRoot] = struct{}{}
	}
	sectorAccessPrice := s.host.SectorAccessPrice.Mul64(uint64(len(sectorAccesses)))
	var bandwidth uint64
	for _, sec := range sections {
		proofHashes := merkle.ProofSize(merkle.SegmentsPerSector, int(sec.Offset), int(sec.Offset+sec.Length))
		bandwidth += uint64(sec.Length) + uint64(proofHashes)*crypto.HashSize
	}
	if bandwidth < renterhost.MinMessageSize {
		bandwidth = renterhost.MinMessageSize
	}
	bandwidthPrice := s.host.DownloadBandwidthPrice.Mul64(bandwidth)
	price := s.host.BaseRPCPrice.Add(sectorAccessPrice).Add(bandwidthPrice)
	if s.contract.Revision().RenterFunds().Cmp(price) < 0 {
		return errors.New("contract has insufficient funds to support download")
	}

	// construct new revision
	rev.NewRevisionNumber++
	newValid, newMissed := updateRevisionOutputs(&rev, price, types.ZeroCurrency)
	renterSig := s.contract.Key().SignHash(crypto.HashObject(rev))

	// send request
	s.extendDeadline(60*time.Second + time.Duration(bandwidth)/time.Microsecond)
	req := &renterhost.RPCReadRequest{
		Sections:    sections,
		MerkleProof: true,

		NewRevisionNumber:    rev.NewRevisionNumber,
		NewValidProofValues:  newValid,
		NewMissedProofValues: newMissed,
		Signature:            renterSig,
	}
	if err := s.sess.WriteRequest(renterhost.RPCReadID, req); err != nil {
		return err
	}

	// host will now stream back responses; ensure we send RPCLoopReadStop
	// before returning
	defer s.sess.WriteResponse(&renterhost.RPCReadStop, nil)
	resp := renterhost.RPCReadResponse{
		Data: s.readBuf[:0], // avoid reallocating
	}
	var hostSig []byte
	for _, sec := range sections {
		if err := s.sess.ReadResponse(&resp, 4096+uint64(sec.Length)); err != nil {
			return err
		}
		// The host may have sent data, a signature, or both. If they sent data,
		// validate it.
		if len(resp.Data) > 0 {
			if len(resp.Data) != int(sec.Length) {
				return errors.New("host did not send enough sector data")
			}
			proofStart := int(sec.Offset) / merkle.SegmentSize
			proofEnd := int(sec.Offset+sec.Length) / merkle.SegmentSize
			if !merkle.VerifyProof(resp.MerkleProof, resp.Data, proofStart, proofEnd, sec.MerkleRoot) {
				return ErrInvalidMerkleProof
			}
			if _, err := w.Write(resp.Data); err != nil {
				return err
			}
		}
		// If the host sent a signature, exit the loop; they won't be sending
		// any more data
		if len(resp.Signature) > 0 {
			hostSig = resp.Signature
			break
		}
	}
	if len(hostSig) == 0 {
		// the host is required to send a signature; if they haven't sent one
		// yet, they should send an empty ReadResponse containing just the
		// signature.
		if err := s.sess.ReadResponse(&resp, 4096); err != nil {
			return err
		}
		hostSig = resp.Signature
	}

	sigs := s.contract.Revision().Signatures
	sigs[0].Signature = renterSig
	sigs[1].Signature = hostSig
	if err := s.contract.SetRevision(ContractRevision{rev, sigs}); err != nil {
		return err
	}

	return nil
}

// Write implements the Write RPC, except for ActionUpdate. A Merkle proof is
// always requested.
func (s *Session) Write(actions []renterhost.RPCWriteAction) error {
	rev := s.contract.Revision().Revision

	// calculate the new Merkle root set and sectors uploaded/stored
	var uploadBandwidth uint64
	newFileSize := rev.NewFileSize
	for _, action := range actions {
		switch action.Type {
		case renterhost.RPCWriteActionAppend:
			uploadBandwidth += renterhost.SectorSize
			newFileSize += renterhost.SectorSize

		case renterhost.RPCWriteActionTrim:
			newFileSize -= renterhost.SectorSize * action.A

		case renterhost.RPCWriteActionSwap:

		default:
			panic("unknown/unsupported action type")
		}
	}
	var storagePrice, collateral types.Currency
	if newFileSize > rev.NewFileSize {
		storageDuration := uint64(rev.NewWindowEnd - s.height)
		storageDuration += 6 // add some leeway in case the host is behind
		collateralDuration := uint64(rev.NewWindowEnd - s.height)
		if collateralDuration >= 6 {
			collateralDuration -= 6 // add some leeway in case we're behind
		}
		sectorStoragePrice := s.host.StoragePrice.Mul64(renterhost.SectorSize).Mul64(storageDuration)
		sectorCollateral := s.host.Collateral.Mul64(renterhost.SectorSize).Mul64(collateralDuration)

		addedSectors := (newFileSize - rev.NewFileSize) / renterhost.SectorSize
		storagePrice = sectorStoragePrice.Mul64(addedSectors)
		collateral = sectorCollateral.Mul64(addedSectors)
	}

	// estimate cost of Merkle proof
	// TODO: calculate exact sizes
	proofSize := merkle.DiffProofSize(actions, int(rev.NewFileSize)/renterhost.SectorSize)
	downloadBandwidth := uint64(proofSize) * crypto.HashSize
	bandwidthPrice := s.host.UploadBandwidthPrice.Mul64(uploadBandwidth).Add(s.host.DownloadBandwidthPrice.Mul64(downloadBandwidth))

	// check that enough funds are available
	price := s.host.BaseRPCPrice.Add(bandwidthPrice).Add(storagePrice)
	if rev.NewValidProofOutputs[0].Value.Cmp(price) < 0 {
		return errors.New("contract has insufficient funds to support modification")
	} else if rev.NewMissedProofOutputs[1].Value.Cmp(collateral) < 0 {
		return errors.New("contract has insufficient collateral to support modification")
	}

	// calculate new revision outputs
	newValid, newMissed := updateRevisionOutputs(&rev, price, collateral)

	// send request
	s.extendDeadline(60*time.Second + time.Duration(uploadBandwidth)/time.Microsecond)
	req := &renterhost.RPCWriteRequest{
		Actions:     actions,
		MerkleProof: true,

		NewRevisionNumber:    rev.NewRevisionNumber + 1,
		NewValidProofValues:  newValid,
		NewMissedProofValues: newMissed,
	}
	if err := s.sess.WriteRequest(renterhost.RPCWriteID, req); err != nil {
		return err
	}

	// read and verify Merkle proof
	var merkleResp renterhost.RPCWriteMerkleProof
	if err := s.sess.ReadResponse(&merkleResp, 4096); err != nil {
		return err
	}
	numSectors := int(rev.NewFileSize / renterhost.SectorSize)
	proofHashes := merkleResp.OldSubtreeHashes
	leafHashes := merkleResp.OldLeafHashes
	oldRoot, newRoot := rev.NewFileMerkleRoot, merkleResp.NewMerkleRoot
	if !merkle.VerifyDiffProof(actions, numSectors, proofHashes, leafHashes, oldRoot, newRoot) {
		err := errors.New("invalid Merkle proof for old root")
		s.sess.WriteResponse(nil, err)
		return err
	}

	// update revision and exchange signatures
	rev.NewRevisionNumber++
	rev.NewFileSize = newFileSize
	rev.NewFileMerkleRoot = newRoot
	renterSig := &renterhost.RPCWriteResponse{
		Signature: s.contract.Key().SignHash(crypto.HashObject(rev)),
	}
	if err := s.sess.WriteResponse(renterSig, nil); err != nil {
		return err
	}
	var hostSig renterhost.RPCWriteResponse
	if err := s.sess.ReadResponse(&hostSig, 4096); err != nil {
		return err
	}

	sigs := s.contract.Revision().Signatures
	sigs[0].Signature = renterSig.Signature
	sigs[1].Signature = hostSig.Signature
	if err := s.contract.SetRevision(ContractRevision{rev, sigs}); err != nil {
		return err
	}

	return nil
}

// Close gracefully terminates the session and closes the underlying connection.
func (s *Session) Close() error {
	return s.sess.Close()
}

// NewSession initiates a new renter-host protocol session with the specified
// host. The supplied contract will be locked and synchronized with the host.
// The host's settings will also be requested.
func NewSession(hostIP modules.NetAddress, contract ContractEditor, currentHeight types.BlockHeight) (*Session, error) {
	s, err := NewUnlockedSession(hostIP, contract.Revision().HostKey(), currentHeight)
	if err != nil {
		return nil, err
	}
	if err := s.Lock(contract); err != nil {
		s.Close()
		return nil, err
	}
	if _, err := s.Settings(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// NewUnlockedSession initiates a new renter-host protocol session with the specified
// host, without locking an associated contract or requesting the host's settings.
func NewUnlockedSession(hostIP modules.NetAddress, hostKey hostdb.HostPublicKey, currentHeight types.BlockHeight) (*Session, error) {
	conn, err := net.Dial("tcp", string(hostIP))
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	s, err := renterhost.NewRenterSession(conn, hostKey)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &Session{
		sess:   s,
		conn:   conn,
		height: currentHeight,
		host: hostdb.ScannedHost{
			PublicKey: hostKey,
		},
	}, nil
}

func updateRevisionOutputs(rev *types.FileContractRevision, cost, collateral types.Currency) (valid, missed []types.Currency) {
	// allocate new slices; don't want to risk accidentally sharing memory
	rev.NewValidProofOutputs = append([]types.SiacoinOutput(nil), rev.NewValidProofOutputs...)
	rev.NewMissedProofOutputs = append([]types.SiacoinOutput(nil), rev.NewMissedProofOutputs...)

	// move valid payout from renter to host
	rev.NewValidProofOutputs[0].Value = rev.NewValidProofOutputs[0].Value.Sub(cost)
	rev.NewValidProofOutputs[1].Value = rev.NewValidProofOutputs[1].Value.Add(cost)

	// move missed payout from renter to void
	rev.NewMissedProofOutputs[0].Value = rev.NewMissedProofOutputs[0].Value.Sub(cost)
	rev.NewMissedProofOutputs[2].Value = rev.NewMissedProofOutputs[2].Value.Add(cost)

	// move collateral from host to void
	rev.NewMissedProofOutputs[1].Value = rev.NewMissedProofOutputs[1].Value.Sub(collateral)
	rev.NewMissedProofOutputs[2].Value = rev.NewMissedProofOutputs[2].Value.Add(collateral)

	return []types.Currency{rev.NewValidProofOutputs[0].Value, rev.NewValidProofOutputs[1].Value},
		[]types.Currency{rev.NewMissedProofOutputs[0].Value, rev.NewMissedProofOutputs[1].Value, rev.NewMissedProofOutputs[2].Value}
}
