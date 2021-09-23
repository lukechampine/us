package host

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"go.sia.tech/siad/crypto"
	"go.sia.tech/siad/modules"
	"go.sia.tech/siad/types"
	"lukechampine.com/frand"
	"lukechampine.com/us/ed25519hash"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renterhost"
)

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

type session struct {
	sess    *renterhost.Session
	ctx     SessionContext
	conn    statsConn
	metrics MetricsRecorder
}

func (s *session) extendDeadline(d time.Duration) { _ = s.conn.SetDeadline(time.Now().Add(d)) }
func (s *session) clearDeadline()                 { _ = s.conn.SetDeadline(time.Time{}) }

func (s *session) readRequest(req renterhost.ProtocolObject) error {
	var maxSize uint64
	var deadline time.Duration
	switch req.(type) {
	case *renterhost.RPCFormContractRequest, *renterhost.RPCRenewAndClearContractRequest:
		maxSize, deadline = modules.TransactionSetSizeLimit, 60*time.Second
	case *renterhost.RPCLockRequest, *renterhost.RPCSectorRootsRequest:
		maxSize, deadline = renterhost.MinMessageSize, 30*time.Second
	case *renterhost.RPCReadRequest:
		maxSize, deadline = renterhost.MinMessageSize*4, 60*time.Second
	case *renterhost.RPCWriteRequest:
		maxSize, deadline = renterhost.SectorSize*5, 120*time.Second
	default:
		panic("unhandled protocol object")
	}
	s.extendDeadline(deadline)
	defer s.clearDeadline()
	return s.sess.ReadRequest(req, maxSize)
}

func (s *session) readResponse(resp renterhost.ProtocolObject) error {
	var maxSize uint64
	var deadline time.Duration
	switch resp.(type) {
	case *renterhost.RPCFormContractAdditions:
		maxSize, deadline = renterhost.MinMessageSize, 60*time.Second
	case *renterhost.RPCFormContractSignatures, *renterhost.RPCRenewAndClearContractSignatures:
		maxSize, deadline = renterhost.MinMessageSize, 30*time.Second
	case *renterhost.RPCWriteResponse, *renterhost.Specifier:
		maxSize, deadline = renterhost.MinMessageSize, 10*time.Second
	default:
		panic("unhandled protocol object")
	}
	s.extendDeadline(deadline)
	defer s.clearDeadline()
	return s.sess.ReadResponse(resp, maxSize)
}

func (s *session) writeResponse(resp renterhost.ProtocolObject) error {
	var deadline time.Duration
	switch resp.(type) {
	case *renterhost.RPCReadResponse, *renterhost.RPCSectorRootsResponse:
		deadline = 120 * time.Second
	case *renterhost.RPCFormContractAdditions:
		deadline = 60 * time.Second
	case *renterhost.RPCFormContractSignatures, *renterhost.RPCRenewAndClearContractSignatures,
		*renterhost.RPCSettingsResponse, *renterhost.RPCLockResponse, *renterhost.RPCWriteMerkleProof:
		deadline = 30 * time.Second
	case *renterhost.RPCWriteResponse:
		deadline = 10 * time.Second
	default:
		panic("unhandled ProtocolObject")
	}
	s.extendDeadline(deadline)
	defer s.clearDeadline()
	return s.sess.WriteResponse(resp, nil)
}

func (s *session) writeError(err error) error {
	s.extendDeadline(10 * time.Second)
	defer s.clearDeadline()
	s.sess.WriteResponse(nil, err)
	return err
}

func (s *session) haveContract() bool {
	return s.ctx.Contract.ParentID != (types.FileContractID{})
}

func (s *session) haveRevisableContract(currentHeight types.BlockHeight) error {
	switch {
	case !s.haveContract():
		return errors.New("no contract locked")
	case s.ctx.Contract.NewRevisionNumber == math.MaxUint64:
		return errors.New("contract has reached maximum revision number")
	case currentHeight+s.ctx.Settings.WindowSize >= s.ctx.Contract.NewWindowEnd:
		return errors.New("refusing further revisions because contract proof window is imminent")
	}
	return nil
}

func (s *session) recordMetric(m Metric) {
	s.ctx.Elapsed = time.Since(s.ctx.Timestamp)
	s.ctx.UpBytes = s.conn.w
	s.ctx.DownBytes = s.conn.r
	s.metrics.RecordSessionMetric(&s.ctx, m)
}

func (s *session) recordMetricRPC(id renterhost.Specifier) (recordEnd func(error)) {
	start := time.Now()
	s.recordMetric(MetricRPCStart{
		ID:        id,
		Timestamp: start,
	})
	oldUp, oldDown := s.conn.w, s.conn.r
	return func(err error) {
		s.recordMetric(MetricRPCEnd{
			ID:        id,
			Elapsed:   time.Since(start),
			UpBytes:   s.conn.w - oldUp,
			DownBytes: s.conn.r - oldDown,
			Err:       err,
		})
	}
}

// A SessionHandler serves renter-host protocol sessions.
type SessionHandler struct {
	secretKey ed25519.PrivateKey
	settings  SettingsReporter
	contracts ContractStore
	sectors   SectorStore
	wallet    Wallet
	tpool     TransactionPool
	metrics   MetricsRecorder
	rpcs      map[renterhost.Specifier]func(*session) error

	// instead of a separate TryMutex for each contract, use a single Cond
	//
	// NOTE: this probably performs worse than than per-contract TryMutexes
	// under heavy load; haven't benchmarked it
	lockCond sync.Cond
	locks    map[types.FileContractID]struct{}
}

func (sh *SessionHandler) lockContract(id types.FileContractID, timeout time.Duration) bool {
	// wake up the cond when the timeout expires
	start := time.Now()
	timer := time.AfterFunc(timeout, sh.lockCond.Broadcast)
	defer timer.Stop()

	sh.lockCond.L.Lock()
	defer sh.lockCond.L.Unlock()
	for {
		if _, ok := sh.locks[id]; !ok {
			// acquire the lock
			sh.locks[id] = struct{}{}
			return true
		} else if time.Since(start) >= timeout {
			return false
		}
		// another session is holding the lock, but we haven't timed out yet
		sh.lockCond.Wait()
	}
}

func (sh *SessionHandler) unlockContract(id types.FileContractID) {
	sh.lockCond.L.Lock()
	delete(sh.locks, id)
	sh.lockCond.Broadcast()
	sh.lockCond.L.Unlock()
}

// Serve serves a renter-host protocol session on the provided connection.
func (sh *SessionHandler) Serve(conn net.Conn) (err error) {
	s := &session{
		ctx: SessionContext{
			UID:         frand.Entropy128(),
			RenterIP:    conn.RemoteAddr().String(),
			Timestamp:   time.Now(),
			BlockHeight: sh.contracts.Height(),
			Settings:    sh.settings.Settings(),
		},
		conn:    statsConn{Conn: conn},
		metrics: sh.metrics,
	}
	s.extendDeadline(60 * time.Second)
	s.sess, err = renterhost.NewHostSession(&s.conn, sh.secretKey)
	s.recordMetric(MetricHandshake{Err: err})
	if err != nil {
		return err
	}
	defer func() { s.recordMetric(MetricSessionEnd{Err: err}) }()
	defer func() { sh.unlockContract(s.ctx.Contract.ID()) }()
	for {
		s.extendDeadline(time.Hour)
		if id, err := s.sess.ReadID(); errors.Is(err, renterhost.ErrRenterClosed) {
			return nil
		} else if err != nil {
			return fmt.Errorf("could not read RPC ID: %w", err)
		} else if rpcFn, ok := sh.rpcs[id]; !ok {
			return s.writeError(fmt.Errorf("invalid or unknown RPC %q", id.String()))
		} else {
			recordEnd := s.recordMetricRPC(id)
			err := rpcFn(s)
			recordEnd(err)
			if err != nil {
				return fmt.Errorf("RPC %q failed: %w", id.String(), err)
			}
		}
	}
}

func (sh *SessionHandler) rpcSettings(s *session) (err error) {
	// NOTE: each time the renter calls this RPC, we can potentially report new
	// settings. That's fine; the important thing is that we never use settings
	// that differ from what the renter has seen.
	s.ctx.Settings = sh.settings.Settings()
	js, _ := json.Marshal(s.ctx.Settings)
	return s.writeResponse(&renterhost.RPCSettingsResponse{
		Settings: js,
	})
}

func (sh *SessionHandler) rpcFormContract(s *session) error {
	var req renterhost.RPCFormContractRequest
	if err := s.readRequest(&req); err != nil {
		return err
	}
	// initialize builder
	if len(req.Transactions) == 0 || len(req.Transactions[len(req.Transactions)-1].FileContracts) == 0 {
		return s.writeError(errors.New("transaction set does not contain a file contract"))
	}
	cb := contractBuilder{
		contract:    req.Transactions[len(req.Transactions)-1].FileContracts[0],
		transaction: req.Transactions[len(req.Transactions)-1],
		parents:     req.Transactions[:len(req.Transactions)-1],
		renterKey:   req.RenterKey,
		hostKey: types.SiaPublicKey{
			Algorithm: types.SignatureEd25519,
			Key:       ed25519hash.ExtractPublicKey(sh.contracts.SigningKey()),
		},
		settings:      s.ctx.Settings,
		currentHeight: s.ctx.BlockHeight,
		minFee:        minFee(sh.tpool),
	}
	defer cb.cleanup()
	if err := validateFormContract(&cb); err != nil {
		return fmt.Errorf("proposed contract was not acceptable: %w", s.writeError(err))
	} else if err := fundContractTransaction(&cb, sh.wallet, sh.tpool); err != nil {
		return fmt.Errorf("could not fund contract transaction: %w", s.writeError(err))
	} else if err := s.writeResponse(&cb.hostAdditions); err != nil {
		return fmt.Errorf("could not send our additions: %w", err)
	} else if err := s.readResponse(&cb.renterSigs); err != nil {
		return fmt.Errorf("could not read renter's signatures: %w", err)
	} else if err := finalizeContract(&cb, sh.wallet, sh.contracts); err != nil {
		return fmt.Errorf("could not finalize contract: %w", s.writeError(err))
	} else if err := sh.tpool.AcceptTransactionSet(append(cb.parents, cb.transaction)); err != nil {
		return fmt.Errorf("transaction pool rejected contract transaction: %w", s.writeError(err))
	} else if err := s.writeResponse(&cb.hostSigs); err != nil {
		return fmt.Errorf("could not send our signatures: %w", err)
	}
	return nil
}

func (sh *SessionHandler) rpcRenewAndClearContract(s *session) error {
	var req renterhost.RPCRenewAndClearContractRequest
	if err := s.readRequest(&req); err != nil {
		return err
	}
	if err := s.haveRevisableContract(sh.contracts.Height()); err != nil {
		return s.writeError(err)
	}

	// initialize builder
	if len(req.Transactions) == 0 || len(req.Transactions[len(req.Transactions)-1].FileContracts) == 0 {
		return s.writeError(errors.New("transaction set does not contain a file contract"))
	}
	cb := contractBuilder{
		contract:    req.Transactions[len(req.Transactions)-1].FileContracts[0],
		transaction: req.Transactions[len(req.Transactions)-1],
		parents:     req.Transactions[:len(req.Transactions)-1],
		renterKey:   req.RenterKey,
		hostKey: types.SiaPublicKey{
			Algorithm: types.SignatureEd25519,
			Key:       ed25519hash.ExtractPublicKey(sh.contracts.SigningKey()),
		},
		settings:      s.ctx.Settings,
		currentHeight: sh.contracts.Height(),
		minFee:        minFee(sh.tpool),
	}
	defer cb.cleanup()
	if err := validateFinalRevision(&cb, s.ctx.Contract, req.FinalValidProofValues, req.FinalMissedProofValues); err != nil {
		return s.writeError(err)
	} else if err := validateRenewContract(&cb, s.ctx.Contract); err != nil {
		return s.writeError(err)
	} else if err := fundRenewalTransaction(&cb, sh.wallet, sh.tpool); err != nil {
		return s.writeError(err)
	} else if err := s.writeResponse(&cb.hostAdditions); err != nil {
		return err
	} else if err := s.readResponse(&cb.renterRenewSigs); err != nil {
		return err
	} else if err := finalizeRenewal(&cb, sh.wallet, sh.contracts, sh.sectors); err != nil {
		return s.writeError(err)
	} else if err := sh.tpool.AcceptTransactionSet(append(cb.parents, cb.transaction)); err != nil {
		return s.writeError(err)
	} else if err := s.writeResponse(&cb.hostRenewSigs); err != nil {
		return err
	}
	s.ctx.Contract = cb.finalRevision
	return nil
}

func (sh *SessionHandler) rpcLock(s *session) error {
	var req renterhost.RPCLockRequest
	if err := s.readRequest(&req); err != nil {
		return err
	}
	if s.haveContract() {
		err := errors.New("another contract is already locked")
		return s.writeError(err)
	}

	contract, err := sh.contracts.Contract(req.ContractID)
	if err != nil || !s.sess.VerifyChallenge(req.Signature, contract.RenterKey().Key) {
		return s.writeError(errors.New("bad signature or no such contract"))
	} else if contract.FatalError != nil {
		return s.writeError(contract.FatalError) // TODO: hide this error from renter?
	} else if !sh.lockContract(req.ContractID, time.Duration(req.Timeout)*time.Millisecond) {
		return s.writeError(errors.New("timed out waiting to lock contract"))
	}
	s.ctx.Contract = contract.Revision

	var newChallenge [16]byte
	frand.Read(newChallenge[:])
	s.sess.SetChallenge(newChallenge)
	return s.writeResponse(&renterhost.RPCLockResponse{
		Acquired:     true,
		NewChallenge: newChallenge,
		Revision:     contract.Revision,
		Signatures:   contract.Signatures[:],
	})
}

func (sh *SessionHandler) rpcUnlock(s *session) error {
	if !s.haveContract() {
		return nil // no contract to unlock
	}
	sh.unlockContract(s.ctx.Contract.ID())
	s.ctx.Contract = types.FileContractRevision{}
	return nil
}

func (sh *SessionHandler) rpcWrite(s *session) error {
	var req renterhost.RPCWriteRequest
	if err := s.readRequest(&req); err != nil {
		return err
	}
	// if no Merkle proof was requested, the renter's signature should be sent
	// immediately
	var sigResponse renterhost.RPCWriteResponse
	if !req.MerkleProof {
		if err := s.readResponse(&sigResponse); err != nil {
			return err
		}
	}

	if err := s.haveRevisableContract(sh.contracts.Height()); err != nil {
		return s.writeError(err)
	}

	// validate actions
	oldSectors := s.ctx.Contract.NewFileSize / renterhost.SectorSize
	if err := validateWriteActions(req.Actions, req.MerkleProof, oldSectors); err != nil {
		return s.writeError(err)
	}

	// compute new Merkle root (and proof, if requested)
	merkleResp, applyModifications, err := considerModifications(s.ctx.Contract.ID(), req.Actions, req.MerkleProof, sh.sectors)
	if err != nil {
		return s.writeError(err)
	}

	// if a Merkle proof was requested, send it and wait for the renter's signature
	if req.MerkleProof {
		if err := s.writeResponse(merkleResp); err != nil {
			return err
		} else if err := s.readResponse(&sigResponse); err != nil {
			return err
		}
	}

	// construct and validate the new revision
	currentRevision := s.ctx.Contract
	newRevision, err := calculateRevision(currentRevision, req.NewRevisionNumber, req.NewValidProofValues, req.NewMissedProofValues)
	if err != nil {
		return s.writeError(err)
	}
	newRevision.NewFileMerkleRoot = merkleResp.NewMerkleRoot
	var rc revisionCharges
	newSectors := oldSectors
	for _, action := range req.Actions {
		switch action.Type {
		case renterhost.RPCWriteActionAppend:
			newRevision.NewFileSize += renterhost.SectorSize
			rc.Up += renterhost.SectorSize
			newSectors++
		case renterhost.RPCWriteActionTrim:
			newRevision.NewFileSize -= renterhost.SectorSize * action.A
			newSectors -= action.A
		case renterhost.RPCWriteActionUpdate:
			rc.Up += uint64(len(action.Data))
			// TODO: this should count as a sector access, but existing renters don't treat it as such
		}
	}
	if newSectors > oldSectors {
		rc.Storage = renterhost.SectorSize * (newSectors - oldSectors)
	}
	if req.MerkleProof {
		rc.Down += crypto.HashSize * uint64(len(merkleResp.OldSubtreeHashes)+len(merkleResp.OldLeafHashes)+1)
	}
	if err := validateRevision(currentRevision, newRevision, rc, s.ctx.Settings, sh.contracts.Height()); err != nil {
		return s.writeError(err)
	}

	// Apply the modifications and sign the revision.
	var resp renterhost.RPCWriteResponse
	if err := applyModifications(); err != nil {
		return s.writeError(err)
	} else if resp.Signature, err = signRevision(newRevision, sigResponse.Signature, sh.contracts); err != nil {
		return s.writeError(err)
	} else if err := s.writeResponse(&resp); err != nil {
		return err
	}
	s.ctx.Contract = newRevision
	return nil
}

func (sh *SessionHandler) rpcSectorRoots(s *session) error {
	var req renterhost.RPCSectorRootsRequest
	if err := s.readRequest(&req); err != nil {
		return err
	}
	if err := s.haveRevisableContract(sh.contracts.Height()); err != nil {
		return s.writeError(err)
	}

	// construct the new revision
	currentRevision := s.ctx.Contract
	newRevision, err := calculateRevision(currentRevision, req.NewRevisionNumber, req.NewValidProofValues, req.NewMissedProofValues)
	if err != nil {
		return s.writeError(err)
	}
	proofSize := merkle.ProofSize(int(currentRevision.NewFileSize/renterhost.SectorSize), int(req.RootOffset), int(req.RootOffset+req.NumRoots))
	rc := revisionCharges{
		Down: (req.NumRoots + uint64(proofSize)) * crypto.HashSize,
	}
	if err := validateRevision(currentRevision, newRevision, rc, s.ctx.Settings, sh.contracts.Height()); err != nil {
		return s.writeError(err)
	}

	resp, err := readSectors(s.ctx.Contract.ID(), req.RootOffset, req.NumRoots, sh.sectors)
	if err != nil {
		return s.writeError(err)
	}

	// commit the new revision
	resp.Signature, err = signRevision(newRevision, req.Signature, sh.contracts)
	if err != nil {
		return s.writeError(err)
	} else if err := s.writeResponse(resp); err != nil {
		return err
	}
	s.ctx.Contract = newRevision
	return nil
}

func (sh *SessionHandler) rpcRead(s *session) error {
	var req renterhost.RPCReadRequest
	if err := s.readRequest(&req); err != nil {
		return err
	}

	// As soon as we finish reading the request, we must begin listening for
	// RPCLoopReadStop, which may arrive at any time, but must arrive before the
	// RPC is considered complete.
	stopSignal := make(chan error, 1)
	go func() {
		var id renterhost.Specifier
		err := s.readResponse(&id)
		if err != nil {
			stopSignal <- err
		} else if id != renterhost.RPCReadStop {
			stopSignal <- errors.New("expected 'stop' from renter, got " + id.String())
		} else {
			stopSignal <- nil
		}
	}()

	if err := s.haveRevisableContract(sh.contracts.Height()); err != nil {
		s.writeError(err)
		<-stopSignal
		return err
	}

	currentRevision := s.ctx.Contract
	for _, sec := range req.Sections {
		switch {
		case uint64(sec.Offset)+uint64(sec.Length) > renterhost.SectorSize:
			return s.writeError(errors.New("request is out-of-bounds"))
		case sec.Length == 0:
			return s.writeError(errors.New("length cannot be zero"))
		case req.MerkleProof && (sec.Offset%merkle.SegmentSize != 0 || sec.Length%merkle.SegmentSize != 0):
			return s.writeError(errors.New("offset and length must be multiples of SegmentSize when requesting a Merkle proof"))
		}
	}

	// construct the new revision
	newRevision, err := calculateRevision(currentRevision, req.NewRevisionNumber, req.NewValidProofValues, req.NewMissedProofValues)
	if err != nil {
		return s.writeError(err)
	}
	var rc revisionCharges
	for _, sec := range req.Sections {
		rc.Down += uint64(sec.Length)
		rc.SectorAccesses++
		if req.MerkleProof {
			start := int(sec.Offset / merkle.SegmentSize)
			end := int((sec.Offset + sec.Length) / merkle.SegmentSize)
			proofSize := merkle.ProofSize(renterhost.SectorSize/merkle.SegmentSize, start, end)
			rc.Down += uint64(proofSize * crypto.HashSize)
		}
	}
	if err := validateRevision(currentRevision, newRevision, rc, s.ctx.Settings, sh.contracts.Height()); err != nil {
		return s.writeError(err)
	}

	// commit the new revision
	hostSig, err := signRevision(newRevision, req.Signature, sh.contracts)
	if err != nil {
		return s.writeError(err)
	}
	s.ctx.Contract = newRevision

	// enter response loop
	for i, sec := range req.Sections {
		resp, err := readSection(sec, req.MerkleProof, sh.sectors)
		if err != nil {
			return s.writeError(err)
		}

		// Send the response. If the renter sent a stop signal, or this is the
		// final response, include our signature in the response.
		select {
		case err := <-stopSignal:
			if err != nil {
				return err
			}
			resp.Signature = hostSig
			return s.writeResponse(resp)
		default:
		}
		if i == len(req.Sections)-1 {
			resp.Signature = hostSig
		}
		if err := s.writeResponse(resp); err != nil {
			return err
		}
	}
	// The stop signal must arrive before RPC is complete.
	return <-stopSignal
}

// NewSessionHandler returns an initialized session manager.
func NewSessionHandler(secretKey ed25519.PrivateKey, sr SettingsReporter, cs ContractStore, ss SectorStore, w Wallet, tp TransactionPool, mr MetricsRecorder) *SessionHandler {
	sh := &SessionHandler{
		secretKey: secretKey,
		settings:  sr,
		contracts: cs,
		sectors:   ss,
		wallet:    w,
		tpool:     tp,
		metrics:   mr,
		lockCond:  sync.Cond{L: new(sync.Mutex)},
		locks:     make(map[types.FileContractID]struct{}),
	}
	sh.rpcs = map[renterhost.Specifier]func(*session) error{
		renterhost.RPCFormContractID:       sh.rpcFormContract,
		renterhost.RPCLockID:               sh.rpcLock,
		renterhost.RPCReadID:               sh.rpcRead,
		renterhost.RPCRenewClearContractID: sh.rpcRenewAndClearContract,
		renterhost.RPCSectorRootsID:        sh.rpcSectorRoots,
		renterhost.RPCSettingsID:           sh.rpcSettings,
		renterhost.RPCUnlockID:             sh.rpcUnlock,
		renterhost.RPCWriteID:              sh.rpcWrite,
	}
	return sh
}
