package proto

import (
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"net"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/ed25519"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renterhost"
)

// ErrInvalidMerkleProof is returned by various RPCs when the host supplies an
// invalid Merkle proof.
var ErrInvalidMerkleProof = errors.New("host supplied invalid Merkle proof")

// wrapResponseErr formats RPC response errors nicely, wrapping them in either
// readCtx or rejectCtx depending on whether we encountered an I/O error or the
// host sent an explicit error message.
func wrapResponseErr(err error, readCtx, rejectCtx string) error {
	err = errors.Cause(err)
	if _, ok := err.(*renterhost.RPCError); ok {
		return errors.Wrap(err, rejectCtx)
	}
	return errors.Wrap(err, readCtx)
}

// A Session is an ongoing exchange of RPCs via the renter-host protocol.
type Session struct {
	sess    *renterhost.Session
	conn    net.Conn
	readBuf [renterhost.SectorSize]byte

	host   hostdb.ScannedHost
	height types.BlockHeight
	rev    ContractRevision
	key    ed25519.PrivateKey
}

// HostKey returns the public key of the host.
func (s *Session) HostKey() hostdb.HostPublicKey { return s.host.PublicKey }

// Revision returns the most recent revision of the locked contract.
func (s *Session) Revision() ContractRevision { return s.rev }

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
	err := s.sess.ReadResponse(resp, 4096)
	return wrapResponseErr(err, fmt.Sprintf("couldn't read %v response", rpcID), fmt.Sprintf("host rejected %v request", rpcID))
}

// Lock calls the Lock RPC, locking the supplied contract and synchronizing its
// state with the host's most recent revision.
func (s *Session) Lock(id types.FileContractID, key ed25519.PrivateKey) (err error) {
	defer wrapErr(&err, "Lock")
	req := &renterhost.RPCLockRequest{
		ContractID: id,
		Signature:  s.sess.SignChallenge(key),
		Timeout:    10e3, // 10 seconds
	}
	s.extendDeadline(15 * time.Second)
	var resp renterhost.RPCLockResponse
	if err := s.call(renterhost.RPCLockID, req, &resp); err != nil {
		return err
	}
	s.sess.SetChallenge(resp.NewChallenge)
	// verify claimed revision
	if len(resp.Signatures) != 2 {
		return errors.Errorf("host returned wrong number of signatures (expected 2, got %v)", len(resp.Signatures))
	}
	revHash := renterhost.HashRevision(resp.Revision)
	if !key.PublicKey().VerifyHash(revHash, resp.Signatures[0].Signature) {
		return errors.New("renter's signature on claimed revision is invalid")
	} else if !s.host.PublicKey.VerifyHash(revHash, resp.Signatures[1].Signature) {
		return errors.New("host's signature on claimed revision is invalid")
	}
	if !resp.Acquired {
		return errors.New("contract is locked by another party")
	}
	s.rev = ContractRevision{
		Revision:   resp.Revision,
		Signatures: [2]types.TransactionSignature{resp.Signatures[0], resp.Signatures[1]},
	}
	s.key = key

	return nil
}

// Unlock calls the Unlock RPC, unlocking the currently-locked contract.
//
// It is typically not necessary to manually unlock a contract, as the host will
// automatically unlock any locked contracts when the connection closes.
func (s *Session) Unlock() (err error) {
	defer wrapErr(&err, "Unlock")
	if s.key == nil {
		return errors.New("no contract locked")
	}
	s.extendDeadline(10 * time.Second)
	if err := s.sess.WriteRequest(renterhost.RPCUnlockID, nil); err != nil {
		return err
	}
	s.rev = ContractRevision{}
	s.key = nil
	return nil
}

// Settings calls the Settings RPC, returning the host's reported settings.
func (s *Session) Settings() (_ hostdb.HostSettings, err error) {
	defer wrapErr(&err, "Settings")
	s.extendDeadline(10 * time.Second)
	var resp renterhost.RPCSettingsResponse
	if err := s.call(renterhost.RPCSettingsID, nil, &resp); err != nil {
		return hostdb.HostSettings{}, err
	} else if err := json.Unmarshal(resp.Settings, &s.host.HostSettings); err != nil {
		return hostdb.HostSettings{}, errors.Wrap(err, "couldn't unmarshal json")
	}
	return s.host.HostSettings, nil
}

// SectorRoots calls the SectorRoots RPC, returning the requested range of
// sector Merkle roots of the currently-locked contract.
func (s *Session) SectorRoots(offset, n int) (_ []crypto.Hash, err error) {
	defer wrapErr(&err, "SectorRoots")
	if offset < 0 || n < 0 || offset+n > s.rev.NumSectors() {
		return nil, errors.New("requested range is out-of-bounds")
	}

	// calculate price
	proofHashes := merkle.ProofSize(s.rev.NumSectors(), offset, offset+n)
	bandwidth := (proofHashes + n) * crypto.HashSize
	if bandwidth < renterhost.MinMessageSize {
		bandwidth = renterhost.MinMessageSize
	}
	bandwidthPrice := s.host.DownloadBandwidthPrice.Mul64(uint64(bandwidth))
	price := s.host.BaseRPCPrice.Add(bandwidthPrice)
	if s.rev.RenterFunds().Cmp(price) < 0 {
		return nil, errors.New("contract has insufficient funds to support sector roots download")
	}

	// construct new revision
	rev := s.rev.Revision
	rev.NewRevisionNumber++
	newValid, newMissed := updateRevisionOutputs(&rev, price, types.ZeroCurrency)

	s.extendDeadline(60*time.Second + time.Duration(bandwidth)/time.Microsecond)
	req := &renterhost.RPCSectorRootsRequest{
		RootOffset: uint64(offset),
		NumRoots:   uint64(n),

		NewRevisionNumber:    rev.NewRevisionNumber,
		NewValidProofValues:  newValid,
		NewMissedProofValues: newMissed,
		Signature:            s.key.SignHash(renterhost.HashRevision(rev)),
	}
	var resp renterhost.RPCSectorRootsResponse
	if err := s.call(renterhost.RPCSectorRootsID, req, &resp); err != nil {
		return nil, err
	}
	s.rev.Revision = rev
	s.rev.Signatures[0].Signature = req.Signature
	s.rev.Signatures[1].Signature = resp.Signature
	if !merkle.VerifySectorRangeProof(resp.MerkleProof, resp.SectorRoots, offset, offset+n, s.rev.NumSectors(), rev.NewFileMerkleRoot) {
		return nil, ErrInvalidMerkleProof
	}
	return resp.SectorRoots, nil
}

// Read calls the Read RPC, writing the requested sections of sector data to w.
// Merkle proofs are always requested.
func (s *Session) Read(w io.Writer, sections []renterhost.RPCReadRequestSection) (err error) {
	defer wrapErr(&err, "Read")

	// calculate price
	sectorAccesses := make(map[crypto.Hash]struct{})
	for _, sec := range sections {
		sectorAccesses[sec.MerkleRoot] = struct{}{}
	}
	sectorAccessPrice := s.host.SectorAccessPrice.Mul64(uint64(len(sectorAccesses)))
	var bandwidth uint64
	for _, sec := range sections {
		// TODO: siad host uses worst-case size. This should be:
		// proofHashes := merkle.ProofSize(merkle.SegmentsPerSector, int(sec.Offset), int(sec.Offset+sec.Length))
		proofHashes := 2 * bits.Len64(merkle.SegmentsPerSector)
		bandwidth += uint64(sec.Length) + uint64(proofHashes)*crypto.HashSize
	}
	if bandwidth < renterhost.MinMessageSize {
		bandwidth = renterhost.MinMessageSize
	}
	bandwidthPrice := s.host.DownloadBandwidthPrice.Mul64(bandwidth)
	price := s.host.BaseRPCPrice.Add(sectorAccessPrice).Add(bandwidthPrice)
	if s.rev.RenterFunds().Cmp(price) < 0 {
		return errors.New("contract has insufficient funds to support download")
	}

	// construct new revision
	rev := s.rev.Revision
	rev.NewRevisionNumber++
	newValid, newMissed := updateRevisionOutputs(&rev, price, types.ZeroCurrency)
	renterSig := s.key.SignHash(renterhost.HashRevision(rev))

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
		return errors.Wrap(err, "couldn't write RPC ID")
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
			return wrapResponseErr(err, "couldn't read sector data", "host rejected Read request")
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
				return errors.Wrap(err, "couldn't write sector data")
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
			return wrapResponseErr(err, "couldn't read signature", "host rejected Read request")
		}
		hostSig = resp.Signature
	}

	s.rev.Revision = rev
	s.rev.Signatures[0].Signature = renterSig
	s.rev.Signatures[1].Signature = hostSig

	return nil
}

// Write implements the Write RPC, except for ActionUpdate. A Merkle proof is
// always requested.
func (s *Session) Write(actions []renterhost.RPCWriteAction) (err error) {
	defer wrapErr(&err, "Write")
	rev := s.rev.Revision

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
	proofSize := merkle.DiffProofSize(actions, s.rev.NumSectors())
	downloadBandwidth := uint64(proofSize) * crypto.HashSize
	bandwidthPrice := s.host.UploadBandwidthPrice.Mul64(uploadBandwidth).Add(s.host.DownloadBandwidthPrice.Mul64(downloadBandwidth))

	// check that enough funds are available
	price := s.host.BaseRPCPrice.Add(bandwidthPrice).Add(storagePrice)
	// NOTE: hosts can be picky about price, so add 5% just to be sure.
	price = price.MulFloat(1.05)
	if rev.NewValidProofOutputs[0].Value.Cmp(price) < 0 {
		return errors.New("contract has insufficient funds to support modification")
	}

	// cap the collateral to whatever is left; no sense complaining if there is
	// insufficient collateral, as we agreed to the amount when we formed the
	// contract
	if collateral.Cmp(rev.NewMissedProofOutputs[1].Value) > 0 {
		collateral = rev.NewMissedProofOutputs[1].Value
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
		return errors.Wrap(err, "couldn't write RPC ID")
	}

	// read and verify Merkle proof
	var merkleResp renterhost.RPCWriteMerkleProof
	if err := s.sess.ReadResponse(&merkleResp, 4096); err != nil {
		return wrapResponseErr(err, "couldn't read Merkle proof response", "host rejected Write request")
	}
	proofHashes := merkleResp.OldSubtreeHashes
	leafHashes := merkleResp.OldLeafHashes
	oldRoot, newRoot := rev.NewFileMerkleRoot, merkleResp.NewMerkleRoot
	// TODO: we skip the Merkle proof if the resulting contract is empty (i.e.
	// if all sectors were deleted) because the proof algorithm chokes on this
	// edge case. Need to investigate what proofs siad hosts are producing (are
	// they valid?) and reconcile those with our Merkle algorithms.
	if newFileSize > 0 && !merkle.VerifyDiffProof(actions, s.rev.NumSectors(), proofHashes, leafHashes, oldRoot, newRoot) {
		err := ErrInvalidMerkleProof
		s.sess.WriteResponse(nil, err)
		return err
	}

	// update revision and exchange signatures
	rev.NewRevisionNumber++
	rev.NewFileSize = newFileSize
	rev.NewFileMerkleRoot = newRoot
	renterSig := &renterhost.RPCWriteResponse{
		Signature: s.key.SignHash(renterhost.HashRevision(rev)),
	}
	if err := s.sess.WriteResponse(renterSig, nil); err != nil {
		return errors.Wrap(err, "couldn't write signature response")
	}
	var hostSig renterhost.RPCWriteResponse
	if err := s.sess.ReadResponse(&hostSig, 4096); err != nil {
		return wrapResponseErr(err, "couldn't read signature response", "host rejected Write signature")
	}

	s.rev.Revision = rev
	s.rev.Signatures[0].Signature = renterSig.Signature
	s.rev.Signatures[1].Signature = hostSig.Signature

	return nil
}

// Close gracefully terminates the session and closes the underlying connection.
func (s *Session) Close() (err error) {
	defer wrapErr(&err, "Close")
	return s.sess.Close()
}

// NewSession initiates a new renter-host protocol session with the specified
// host. The supplied contract will be locked and synchronized with the host.
// The host's settings will also be requested.
func NewSession(hostIP modules.NetAddress, hostKey hostdb.HostPublicKey, id types.FileContractID, key ed25519.PrivateKey, currentHeight types.BlockHeight) (_ *Session, err error) {
	defer wrapErr(&err, "NewSession")
	s, err := newUnlockedSession(hostIP, hostKey, currentHeight)
	if err != nil {
		return nil, err
	}
	if err := s.Lock(id, key); err != nil {
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
func NewUnlockedSession(hostIP modules.NetAddress, hostKey hostdb.HostPublicKey, currentHeight types.BlockHeight) (_ *Session, err error) {
	defer wrapErr(&err, "NewUnlockedSession")
	return newUnlockedSession(hostIP, hostKey, currentHeight)
}

// same as above, but without error wrapping, since we call it from NewSession too.
func newUnlockedSession(hostIP modules.NetAddress, hostKey hostdb.HostPublicKey, currentHeight types.BlockHeight) (_ *Session, err error) {
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
