package proto

import (
	"bufio"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/bits"
	"net"
	"sort"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/ed25519hash"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renterhost"
)

var (
	// ErrInsufficientFunds is returned by various RPCs when the renter is
	// unable to provide sufficient payment to the host.
	ErrInsufficientFunds = errors.New("insufficient funds")

	// ErrInvalidMerkleProof is returned by various RPCs when the host supplies
	// an invalid Merkle proof.
	ErrInvalidMerkleProof = errors.New("host supplied invalid Merkle proof")

	// ErrContractLocked is returned by the Lock RPC when the contract in
	// question is already locked by another party. This is a transient error;
	// the caller should retry later.
	ErrContractLocked = errors.New("contract is locked by another party")

	// ErrNoContractLocked is returned by RPCs that require a locked contract
	// when no contract is locked.
	ErrNoContractLocked = errors.New("no contract locked")

	// ErrContractFinalized is returned by the Lock RPC when the contract in
	// question has reached its maximum revision number, meaning the contract
	// can no longer be revised.
	ErrContractFinalized = errors.New("contract cannot be revised further")
)

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

type statsConn struct {
	net.Conn
	r, w uint64
}

func (sc *statsConn) Read(p []byte) (int, error) {
	n, err := sc.Conn.Read(p)
	sc.r += uint64(n)
	return n, err
}

func (sc *statsConn) Write(p []byte) (int, error) {
	n, err := sc.Conn.Write(p)
	sc.w += uint64(n)
	return n, err
}

// A Session is an ongoing exchange of RPCs via the renter-host protocol.
type Session struct {
	sess        *renterhost.Session
	conn        *statsConn
	appendRoots []crypto.Hash

	latency       time.Duration
	readDeadline  time.Duration
	writeDeadline time.Duration
	stats         RPCStatsRecorder

	host   hostdb.ScannedHost
	height types.BlockHeight
	rev    ContractRevision
	key    ed25519.PrivateKey
}

// HostKey returns the public key of the host.
func (s *Session) HostKey() hostdb.HostPublicKey { return s.host.PublicKey }

// Revision returns the most recent revision of the locked contract.
func (s *Session) Revision() ContractRevision { return s.rev }

// IsClosed returns whether the Session is closed.
func (s *Session) IsClosed() bool { return s.sess.IsClosed() }

// SetLatency sets the latency deadline for RPCs.
func (s *Session) SetLatency(d time.Duration) { s.latency = d }

// SetReadDeadline sets the per-byte read deadline for RPCs. For example, to
// time out after 1 minute when downloading a sector, set the per-byte deadline
// to time.Minute / renterhost.SectorSize.
func (s *Session) SetReadDeadline(d time.Duration) { s.readDeadline = d }

// SetWriteDeadline sets the per-byte write deadline for RPCs. For example, to
// time out after 1 minute when uploading a sector, set the per-byte deadline to
// time.Minute / renterhost.SectorSize.
func (s *Session) SetWriteDeadline(d time.Duration) { s.writeDeadline = d }

func (s *Session) extendDeadline(d time.Duration) {
	_ = s.conn.SetDeadline(time.Now().Add(s.latency + d))
}

func (s *Session) extendBandwidthDeadline(up, down uint64) {
	if up < renterhost.MinMessageSize {
		up = renterhost.MinMessageSize
	}
	if down < renterhost.MinMessageSize {
		down = renterhost.MinMessageSize
	}
	s.extendDeadline(s.writeDeadline*time.Duration(up) + s.readDeadline*time.Duration(down))
}

// SetRPCStatsRecorder sets the RPCStatsRecorder for the Session.
func (s *Session) SetRPCStatsRecorder(stats RPCStatsRecorder) { s.stats = stats }

func (s *Session) collectStats(id renterhost.Specifier, err *error) (record func()) {
	if s.stats == nil {
		return func() {}
	}
	stats := RPCStats{
		Host:      s.host.PublicKey,
		Contract:  s.rev.Revision.ID(),
		RPC:       id,
		Timestamp: time.Now(),
	}
	var startFunds types.Currency
	if s.rev.IsValid() {
		startFunds = s.rev.RenterFunds()
	}
	oldW, oldR := s.conn.w, s.conn.r
	return func() {
		stats.Err = *err
		stats.Elapsed = time.Since(stats.Timestamp)
		stats.Uploaded = s.conn.w - oldW
		stats.Downloaded = s.conn.r - oldR
		if s.rev.IsValid() && startFunds.Cmp(s.rev.RenterFunds()) > 0 {
			stats.Cost = startFunds.Sub(s.rev.RenterFunds())
		}
		s.stats.RecordRPCStats(stats)
	}
}

// call is a helper method that writes a request and then reads a response.
func (s *Session) call(rpcID renterhost.Specifier, req, resp renterhost.ProtocolObject) error {
	if err := s.sess.WriteRequest(rpcID, req); err != nil {
		return err
	}
	// use a maxlen large enough for all RPCs except Read, Write, and
	// SectorRoots (which don't use call anyway)
	err := s.sess.ReadResponse(resp, 4096)
	return wrapResponseErr(err, fmt.Sprintf("couldn't read %v response", rpcID), fmt.Sprintf("host rejected %v request", rpcID))
}

func (s *Session) isLocked() bool    { return s.rev.IsValid() }
func (s *Session) isRevisable() bool { return s.rev.Revision.NewRevisionNumber < math.MaxUint64 }

func (s *Session) sufficientFunds(price types.Currency) bool {
	if !s.rev.IsValid() {
		// all calls to sufficientFunds should be guarded with isLocked checks
		panic("sufficientFunds called with invalid revision")
	}
	// We need some funds in order to renew a contract; specifically, we need to
	// pay the host's BaseRPCPrice. Since the host may increase their price,
	// multiply it by 5 just to be safe.
	renewPrice := s.host.BaseRPCPrice.Mul64(5)
	return s.rev.RenterFunds().Cmp(price.Add(renewPrice)) >= 0
}

// Lock calls the Lock RPC, locking the supplied contract and synchronizing its
// state with the host's most recent revision. The timeout specifies how long
// the host should wait while attempting to acquire the lock. Note that timeouts
// are serialized in milliseconds, so a timeout of less than 1ms will be rounded
// down to 0. (A timeout of 0 is valid: it means that the lock will only be
// acquired if the contract is unlocked at the moment the host receives the
// RPC.)
//
// Lock returns ErrContractFinalized if the contract can no longer be revised.
// The contract will still be available via the Revision method, but invoking
// other RPCs may result in errors or panics.
func (s *Session) Lock(id types.FileContractID, key ed25519.PrivateKey, timeout time.Duration) (err error) {
	defer wrapErr(&err, "Lock")
	defer s.collectStats(renterhost.RPCLockID, &err)()
	req := &renterhost.RPCLockRequest{
		ContractID: id,
		Signature:  s.sess.SignChallenge(key),
		Timeout:    uint64(timeout.Milliseconds()),
	}
	s.extendDeadline(time.Duration(req.Timeout) * time.Millisecond)
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
	if !ed25519hash.Verify(ed25519hash.ExtractPublicKey(key), revHash, resp.Signatures[0].Signature) {
		return errors.New("renter's signature on claimed revision is invalid")
	} else if !ed25519hash.Verify(s.host.PublicKey.Ed25519(), revHash, resp.Signatures[1].Signature) {
		return errors.New("host's signature on claimed revision is invalid")
	}
	if !resp.Acquired {
		return ErrContractLocked
	}
	s.rev = ContractRevision{
		Revision:   resp.Revision,
		Signatures: [2]types.TransactionSignature{resp.Signatures[0], resp.Signatures[1]},
	}
	s.key = key

	if s.rev.Revision.NewRevisionNumber == math.MaxUint64 {
		return ErrContractFinalized
	}
	return nil
}

// Unlock calls the Unlock RPC, unlocking the currently-locked contract.
//
// It is typically not necessary to manually unlock a contract, as the host will
// automatically unlock any locked contracts when the connection closes.
func (s *Session) Unlock() (err error) {
	defer wrapErr(&err, "Unlock")
	defer s.collectStats(renterhost.RPCUnlockID, &err)()
	if s.key == nil {
		return errors.New("no contract locked")
	}
	s.extendBandwidthDeadline(renterhost.MinMessageSize, renterhost.MinMessageSize)
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
	defer s.collectStats(renterhost.RPCSettingsID, &err)()
	s.extendBandwidthDeadline(renterhost.MinMessageSize, renterhost.MinMessageSize)
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
	defer s.collectStats(renterhost.RPCSectorRootsID, &err)()

	if !s.isLocked() {
		return nil, ErrNoContractLocked
	} else if !s.isRevisable() {
		return nil, ErrContractFinalized
	} else if offset < 0 || n < 0 || offset+n > s.rev.NumSectors() {
		return nil, errors.New("requested range is out-of-bounds")
	} else if n == 0 {
		return nil, nil
	}

	// calculate price
	proofHashes := merkle.ProofSize(s.rev.NumSectors(), offset, offset+n)
	downloadBandwidth := uint64(proofHashes+n) * crypto.HashSize
	if downloadBandwidth < renterhost.MinMessageSize {
		downloadBandwidth = renterhost.MinMessageSize
	}
	bandwidthPrice := s.host.DownloadBandwidthPrice.Mul64(downloadBandwidth)
	price := s.host.BaseRPCPrice.Add(bandwidthPrice)
	if !s.sufficientFunds(price) {
		return nil, ErrInsufficientFunds
	}

	// construct new revision
	rev := s.rev.Revision
	rev.NewRevisionNumber++
	newValid, newMissed := updateRevisionOutputs(&rev, price, types.ZeroCurrency)

	s.extendBandwidthDeadline(renterhost.MinMessageSize, downloadBandwidth)
	req := &renterhost.RPCSectorRootsRequest{
		RootOffset: uint64(offset),
		NumRoots:   uint64(n),

		NewRevisionNumber:    rev.NewRevisionNumber,
		NewValidProofValues:  newValid,
		NewMissedProofValues: newMissed,
		Signature:            ed25519hash.Sign(s.key, renterhost.HashRevision(rev)),
	}
	var resp renterhost.RPCSectorRootsResponse
	if err := s.sess.WriteRequest(renterhost.RPCSectorRootsID, req); err != nil {
		return nil, err
	}
	if err := s.sess.ReadResponse(&resp, uint64(4096+32*n)); err != nil {
		readCtx := fmt.Sprintf("couldn't read %v response", renterhost.RPCSectorRootsID)
		rejectCtx := fmt.Sprintf("host rejected %v request", renterhost.RPCSectorRootsID)
		return nil, wrapResponseErr(err, readCtx, rejectCtx)
	}
	s.rev.Revision = rev
	s.rev.Signatures[0].Signature = req.Signature
	s.rev.Signatures[1].Signature = resp.Signature
	if !merkle.VerifySectorRangeProof(resp.MerkleProof, resp.SectorRoots, offset, offset+n, s.rev.NumSectors(), rev.NewFileMerkleRoot) {
		return nil, ErrInvalidMerkleProof
	}
	return resp.SectorRoots, nil
}

// helper type for ensuring that we always write in multiples of SegmentSize,
// which is required by e.g. (renter.KeySeed).XORKeyStream
type segWriter struct {
	w   io.Writer
	buf [merkle.SegmentSize * 64]byte
	len int
}

func (sw *segWriter) Write(p []byte) (int, error) {
	lenp := len(p)
	for len(p) > 0 {
		n := copy(sw.buf[sw.len:], p)
		sw.len += n
		p = p[n:]
		segs := sw.buf[:sw.len-(sw.len%merkle.SegmentSize)]
		if _, err := sw.w.Write(segs); err != nil {
			return 0, err
		}
		sw.len = copy(sw.buf[:], sw.buf[len(segs):sw.len])
	}
	return lenp, nil
}

// Read calls the Read RPC, writing the requested sections of sector data to w.
// Merkle proofs are always requested.
//
// Note that sector data is streamed to w before it has been validated. Callers
// MUST check the returned error, and discard any data written to w if the error
// is non-nil. Failure to do so may allow an attacker to inject malicious data.
func (s *Session) Read(w io.Writer, sections []renterhost.RPCReadRequestSection) (err error) {
	defer wrapErr(&err, "Read")
	defer s.collectStats(renterhost.RPCReadID, &err)()

	if !s.isLocked() {
		return ErrNoContractLocked
	} else if !s.isRevisable() {
		return ErrContractFinalized
	} else if len(sections) == 0 {
		return nil
	}

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
	if !s.sufficientFunds(price) {
		return ErrInsufficientFunds
	}

	// construct new revision
	rev := s.rev.Revision
	rev.NewRevisionNumber++
	newValid, newMissed := updateRevisionOutputs(&rev, price, types.ZeroCurrency)
	renterSig := ed25519hash.Sign(s.key, renterhost.HashRevision(rev))

	// send request
	uploadBandwidth := 4096 + 4096*uint64(len(sections))
	downloadBandwidth := bandwidth + 4096*uint64(len(sections))
	s.extendBandwidthDeadline(uploadBandwidth, downloadBandwidth)
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
	var hostSig []byte
	for _, sec := range sections {
		// NOTE: normally, we would call ReadResponse here to read an AEAD RPC
		// message, verify the tag and decrypt, and then pass the data to
		// merkle.VerifyProof. As an optimization, we instead stream the message
		// through a Merkle proof verifier before verifying the AEAD tag.
		// Security therefore depends on the caller of Read discarding any data
		// written to w in the event that verification fails.
		msgReader, err := s.sess.RawResponse(4096 + uint64(sec.Length))
		if err != nil {
			return wrapResponseErr(err, "couldn't read sector data", "host rejected Read request")
		}
		// Read the signature, which may or may not be present.
		lenbuf := make([]byte, 8)
		if _, err := io.ReadFull(msgReader, lenbuf); err != nil {
			return errors.Wrap(err, "couldn't read signature len")
		}
		if n := binary.LittleEndian.Uint64(lenbuf); n > 0 {
			hostSig = make([]byte, n)
			if _, err := io.ReadFull(msgReader, hostSig); err != nil {
				return errors.Wrap(err, "couldn't read signature")
			}
		}
		// stream the sector data into w and the proof verifier
		if _, err := io.ReadFull(msgReader, lenbuf); err != nil {
			return errors.Wrap(err, "couldn't read data len")
		} else if binary.LittleEndian.Uint64(lenbuf) != uint64(sec.Length) {
			return errors.New("host sent wrong amount of sector data")
		}
		proofStart := int(sec.Offset) / merkle.SegmentSize
		proofEnd := int(sec.Offset+sec.Length) / merkle.SegmentSize
		rpv := merkle.NewRangeProofVerifier(proofStart, proofEnd)
		tee := io.TeeReader(io.LimitReader(msgReader, int64(sec.Length)), &segWriter{w: w})
		// the proof verifier Reads one segment at a time, so bufio is crucial
		// for performance here
		if _, err := rpv.ReadFrom(bufio.NewReaderSize(tee, 1<<16)); err != nil {
			return errors.Wrap(err, "couldn't stream sector data")
		}
		// read the Merkle proof
		if _, err := io.ReadFull(msgReader, lenbuf); err != nil {
			return errors.Wrap(err, "couldn't read proof len")
		}
		if binary.LittleEndian.Uint64(lenbuf) != uint64(merkle.ProofSize(merkle.SegmentsPerSector, proofStart, proofEnd)) {
			return errors.New("invalid proof size")
		}
		proof := make([]crypto.Hash, binary.LittleEndian.Uint64(lenbuf))
		for i := range proof {
			if _, err := io.ReadFull(msgReader, proof[i][:]); err != nil {
				return errors.Wrap(err, "couldn't read Merkle proof")
			}
		}
		// verify the message tag and the Merkle proof
		if err := msgReader.VerifyTag(); err != nil {
			return err
		}
		if !rpv.Verify(proof, sec.MerkleRoot) {
			return ErrInvalidMerkleProof
		}
		// if the host sent a signature, exit the loop; they won't be sending
		// any more data
		if len(hostSig) > 0 {
			break
		}
	}
	if len(hostSig) == 0 {
		// the host is required to send a signature; if they haven't sent one
		// yet, they should send an empty ReadResponse containing just the
		// signature.
		var resp renterhost.RPCReadResponse
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
	defer s.collectStats(renterhost.RPCWriteID, &err)()

	if !s.isLocked() {
		return ErrNoContractLocked
	} else if !s.isRevisable() {
		return ErrContractFinalized
	} else if len(actions) == 0 {
		return nil
	}
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
	if !s.sufficientFunds(price) {
		return ErrInsufficientFunds
	}
	// hosts can also be picky about collateral, so subtract 5%.
	collateral = collateral.MulFloat(0.95)

	// cap the collateral to whatever is left; no sense complaining if there is
	// insufficient collateral, as we agreed to the amount when we formed the
	// contract
	if collateral.Cmp(rev.NewMissedProofOutputs[1].Value) > 0 {
		collateral = rev.NewMissedProofOutputs[1].Value
	}

	// calculate new revision outputs
	newValid, newMissed := updateRevisionOutputs(&rev, price, collateral)

	// compute appended roots in parallel with I/O
	precompChan := make(chan struct{})
	go func() {
		s.appendRoots = merkle.PrecomputeAppendRoots(actions)
		close(precompChan)
	}()
	// ensure that the goroutine has exited before we return
	defer func() { <-precompChan }()

	// send request
	uploadBandwidth += 4096 * uint64(len(actions))
	s.extendBandwidthDeadline(uploadBandwidth, downloadBandwidth)
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
		return wrapResponseErr(err, "couldn't read Merkle proof response", "host rejected Write request")
	}
	proofHashes := merkleResp.OldSubtreeHashes
	leafHashes := merkleResp.OldLeafHashes
	oldRoot, newRoot := rev.NewFileMerkleRoot, merkleResp.NewMerkleRoot
	// TODO: we skip the Merkle proof if the resulting contract is empty (i.e.
	// if all sectors were deleted) because the proof algorithm chokes on this
	// edge case. Need to investigate what proofs siad hosts are producing (are
	// they valid?) and reconcile those with our Merkle algorithms.
	<-precompChan
	if newFileSize > 0 && !merkle.VerifyDiffProof(actions, s.rev.NumSectors(), proofHashes, leafHashes, oldRoot, newRoot, s.appendRoots) {
		err := ErrInvalidMerkleProof
		s.sess.WriteResponse(nil, err)
		return err
	}

	// update revision and exchange signatures
	rev.NewRevisionNumber++
	rev.NewFileSize = newFileSize
	rev.NewFileMerkleRoot = newRoot
	renterSig := &renterhost.RPCWriteResponse{
		Signature: ed25519hash.Sign(s.key, renterhost.HashRevision(rev)),
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

// Append calls the Write RPC with a single action, appending the provided
// sector. It returns the Merkle root of the sector.
func (s *Session) Append(sector *[renterhost.SectorSize]byte) (crypto.Hash, error) {
	err := s.Write([]renterhost.RPCWriteAction{{
		Type: renterhost.RPCWriteActionAppend,
		Data: sector[:],
	}})
	if err != nil {
		return crypto.Hash{}, err
	}
	return s.appendRoots[0], nil
}

// DeleteSectors calls the Write RPC with a set of Swap and Trim actions that
// delete the specified sectors.
func (s *Session) DeleteSectors(roots []crypto.Hash) error {
	if len(roots) == 0 {
		return nil
	}

	// download the full set of SectorRoots
	numRoots := s.Revision().NumSectors()
	rootIndices := make(map[crypto.Hash]int, numRoots)
	for offset := 0; offset < numRoots; {
		n := 130000 // a little less than 4MiB of roots
		if offset+n > numRoots {
			n = numRoots - offset
		}
		roots, err := s.SectorRoots(offset, n)
		if err != nil {
			return err
		}
		for i, root := range roots {
			rootIndices[root] = offset + i
		}
		offset += n
	}

	// look up the index of each sector
	badIndices := make([]int, 0, len(roots))
	for _, r := range roots {
		// if a root isn't present, skip it; the caller probably deleted it
		// previously
		if index, ok := rootIndices[r]; ok {
			badIndices = append(badIndices, index)
			// deleting here ensures that we only add each root index once, i.e.
			// it guards against duplicates in roots
			delete(rootIndices, r)
		}
	}
	// sort in descending order so that we can use 'range'
	sort.Sort(sort.Reverse(sort.IntSlice(badIndices)))

	// iterate backwards from the end of the contract, swapping each "good"
	// sector with one of the "bad" sectors.
	var actions []renterhost.RPCWriteAction
	cIndex := s.Revision().NumSectors() - 1
	for _, rIndex := range badIndices {
		if cIndex != rIndex {
			// swap a "good" sector for a "bad" sector
			actions = append(actions, renterhost.RPCWriteAction{
				Type: renterhost.RPCWriteActionSwap,
				A:    uint64(cIndex),
				B:    uint64(rIndex),
			})
		}
		cIndex--
	}
	// trim all "bad" sectors
	actions = append(actions, renterhost.RPCWriteAction{
		Type: renterhost.RPCWriteActionTrim,
		A:    uint64(len(badIndices)),
	})

	// request the swap+delete operation
	//
	// NOTE: siad hosts will accept up to 20 MiB of data in the request,
	// which should be sufficient to delete up to 2.5 TiB of sector data
	// at a time.
	return s.Write(actions)
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
	defer wrapErrWithReplace(&err, "NewSession")
	s, err := NewUnlockedSession(hostIP, hostKey, currentHeight)
	if err != nil {
		return nil, err
	}
	if err := s.Lock(id, key, 10*time.Second); err != nil {
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
	defer wrapErrWithReplace(&err, "NewUnlockedSession")
	conn, err := net.DialTimeout("tcp", string(hostIP), 60*time.Second)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	return NewUnlockedSessionFromConn(conn, hostKey, currentHeight)
}

// NewUnlockedSessionFromConn initiates a new renter-host protocol session on
// top of the provided conn, without locking an associated contract or
// requesting the host's settings. The conn should have a deadline appropriate
// for the renter-host protocol handshake.
func NewUnlockedSessionFromConn(conn net.Conn, hostKey hostdb.HostPublicKey, currentHeight types.BlockHeight) (_ *Session, err error) {
	defer wrapErr(&err, "NewUnlockedSessionFromConn")
	sc := &statsConn{Conn: conn}
	start := time.Now()
	s, err := renterhost.NewRenterSession(sc, hostKey.Ed25519())
	if err != nil {
		sc.Close()
		return nil, err
	}
	latency := time.Since(start)
	return &Session{
		sess:   s,
		conn:   sc,
		height: currentHeight,
		host: hostdb.ScannedHost{
			PublicKey: hostKey,
		},
		// extremely generous default deadlines
		latency:       time.Second + latency*3,
		readDeadline:  time.Millisecond,
		writeDeadline: time.Millisecond,
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
