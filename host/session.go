package host

import (
	"crypto/ed25519"
	"encoding/json"
	"math"
	"net"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/frand"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renterhost"
)

type session struct {
	sess     *renterhost.Session
	ctx      SessionContext
	conn     net.Conn
	contract types.FileContractRevision
	metrics  MetricsRecorder
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
		panic("unhandled protocol object")
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

func (s *session) haveContract(revisable bool) error {
	if s.contract.ParentID == (types.FileContractID{}) {
		return errors.New("no contract locked")
	} else if revisable && s.contract.NewRevisionNumber == math.MaxUint64 {
		return errors.New("contract cannot be revised")
	}
	return nil
}

func (s *session) recordMetric(m Metric) {
	if s.metrics == nil {
		return
	}
	s.ctx.Elapsed = time.Since(s.ctx.Timestamp)
	s.metrics.RecordSessionMetric(&s.ctx, m)
}

func (s *session) recordMetricRPC(id renterhost.Specifier) (recordEnd func(error)) {
	if s.metrics == nil {
		return func(error) {}
	}
	start := time.Now()
	s.recordMetric(MetricRPCStart{
		ID:        id,
		Timestamp: start,
		Contract:  s.contract,
	})
	return func(err error) {
		s.recordMetric(MetricRPCEnd{
			ID:       id,
			Elapsed:  time.Since(start),
			Contract: s.contract,
			Err:      err,
		})
	}
}

// SessionManager ...
type SessionManager struct {
	secretKey ed25519.PrivateKey
	settings  SettingsManager
	contracts *ContractManager
	storage   *StorageManager
	wallet    *WalletManager
	chain     *ChainManager
	metrics   MetricsRecorder
	rpcs      map[renterhost.Specifier]func(*session) error
}

// Listen ...
func (sm *SessionManager) Listen(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			err := sm.handleConn(conn)
			if err != nil {
				println("rpc error:", err.Error()) // TODO
			}
		}()
	}
}

func (sm *SessionManager) handleConn(conn net.Conn) (err error) {
	s := &session{
		ctx: SessionContext{
			UID:       frand.Entropy128(),
			RenterIP:  conn.RemoteAddr().String(),
			Timestamp: time.Now(),
		},
		conn:    conn,
		metrics: sm.metrics,
	}
	s.extendDeadline(60 * time.Second)
	s.sess, err = renterhost.NewHostSession(conn, sm.secretKey)
	s.recordMetric(MetricHandshake{Err: err})
	if err != nil {
		return err
	}
	defer func() { s.recordMetric(MetricSessionEnd{Err: err}) }()
	for {
		s.extendDeadline(time.Hour)
		id, err := s.sess.ReadID()
		if errors.Cause(err) == renterhost.ErrRenterClosed {
			return nil
		} else if err != nil {
			return errors.Wrap(err, "could not read RPC ID")
		} else if rpcFn, ok := sm.rpcs[id]; !ok {
			return s.writeError(errors.Errorf("invalid or unknown RPC %q", id.String()))
		} else {
			recordEnd := s.recordMetricRPC(id)
			err := rpcFn(s)
			recordEnd(err)
			if err != nil {
				return errors.Wrapf(err, "RPC %q failed", id.String())
			}
		}
	}
}

func (sm *SessionManager) rpcSettings(s *session) (err error) {
	js, _ := json.Marshal(sm.settings.Settings())
	return s.writeResponse(&renterhost.RPCSettingsResponse{
		Settings: js,
	})
}

func (sm *SessionManager) rpcFormContract(s *session) error {
	var req renterhost.RPCFormContractRequest
	if err := s.readRequest(&req); err != nil {
		return err
	}
	if len(req.Transactions) == 0 || len(req.Transactions[len(req.Transactions)-1].FileContracts) == 0 {
		return s.writeError(errors.New("transaction set does not contain a file contract"))
	}
	cb := &contractBuilder{
		contract:      req.Transactions[len(req.Transactions)-1].FileContracts[0],
		transaction:   req.Transactions[len(req.Transactions)-1],
		parents:       req.Transactions[:len(req.Transactions)-1],
		renterKey:     req.RenterKey,
		settings:      sm.settings.Settings(),
		currentHeight: sm.chain.CurrentHeight(),
		minFee:        sm.chain.MinFee(),
	}
	if err := sm.contracts.ConsiderFormRequest(cb); err != nil {
		return s.writeError(err)
	} else if err := sm.wallet.FundContract(cb); err != nil {
		return s.writeError(err)
	} else if err := s.writeResponse(&cb.hostAdditions); err != nil {
		return err
	} else if err := s.readResponse(&cb.renterSigs); err != nil {
		return err
	} else if err := sm.wallet.SignContract(cb); err != nil {
		return s.writeError(err)
	} else if err := sm.chain.BroadcastTransactionSet(append(cb.parents, cb.transaction)); err != nil {
		return s.writeError(err)
	} else if err := sm.contracts.AcceptContract(cb); err != nil {
		return s.writeError(err)
	} else if err := s.writeResponse(&cb.hostSigs); err != nil {
		return err
	}
	return nil
}

func (sm *SessionManager) rpcRenewAndClearContract(s *session) error {
	var req renterhost.RPCRenewAndClearContractRequest
	if err := s.readRequest(&req); err != nil {
		return err
	}
	if err := s.haveContract(true); err != nil {
		return s.writeError(err)
	}

	// initialize builder
	if len(req.Transactions) == 0 || len(req.Transactions[len(req.Transactions)-1].FileContracts) == 0 {
		return s.writeError(errors.New("transaction set does not contain a file contract"))
	}
	cb := &contractBuilder{
		contract:      req.Transactions[len(req.Transactions)-1].FileContracts[0],
		transaction:   req.Transactions[len(req.Transactions)-1],
		parents:       req.Transactions[:len(req.Transactions)-1],
		renterKey:     req.RenterKey,
		settings:      sm.settings.Settings(),
		currentHeight: sm.chain.CurrentHeight(),
		minFee:        sm.chain.MinFee(),
	}
	if err := sm.contracts.ConsiderFinalRevision(cb, s.contract, req.FinalValidProofValues, req.FinalMissedProofValues); err != nil {
		return s.writeError(err)
	} else if err := sm.contracts.ConsiderRenewRequest(cb, s.contract); err != nil {
		return s.writeError(err)
	} else if err := sm.wallet.FundRenewal(cb); err != nil {
		return s.writeError(err)
	} else if err := s.writeResponse(&cb.hostAdditions); err != nil {
		return err
	} else if err := s.readResponse(&cb.renterRenewSigs); err != nil {
		return err
	} else if err := sm.wallet.SignRenewal(cb); err != nil {
		return s.writeError(err)
	} else if err := sm.chain.BroadcastTransactionSet(append(cb.parents, cb.transaction)); err != nil {
		return s.writeError(err)
	} else if err := sm.contracts.AcceptRenewal(cb); err != nil {
		return s.writeError(err)
	} else if err := sm.storage.MoveContractRoots(s.contract.ParentID, cb.transaction.FileContractID(0)); err != nil {
		return s.writeError(err)
	} else if err := s.writeResponse(&cb.hostRenewSigs); err != nil {
		return err
	}
	s.contract = cb.finalRevision
	return nil
}

func (sm *SessionManager) rpcLock(s *session) error {
	var req renterhost.RPCLockRequest
	if err := s.readRequest(&req); err != nil {
		return err
	}
	if s.haveContract(false) == nil {
		err := errors.New("another contract is already locked")
		return s.writeError(err)
	}

	contract, err := sm.contracts.Acquire(req.ContractID, time.Duration(req.Timeout)*time.Millisecond)
	if err != nil || !s.sess.VerifyChallenge(req.Signature, hostdb.HostKeyFromSiaPublicKey(contract.RenterKey()).Ed25519()) {
		return s.writeError(errors.New("bad signature or no such contract"))
	} else if !sm.chain.SuspendRevisionSubmission(req.ContractID) {
		return s.writeError(errors.New("no longer accepting revisions for that contract"))
	}
	s.contract = contract.Revision

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

func (sm *SessionManager) rpcUnlock(s *session) error {
	if err := s.haveContract(false); err != nil {
		return err // no contract to unlock
	}
	err := sm.contracts.Release(s.contract.ID())
	sm.chain.ResumeRevisionSubmission(s.contract.ID())
	s.contract = types.FileContractRevision{}
	return err
}

func (sm *SessionManager) rpcWrite(s *session) error {
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

	if err := s.haveContract(true); err != nil {
		return s.writeError(err)
	}

	// validate actions
	oldSectors := s.contract.NewFileSize / renterhost.SectorSize
	newSectors := oldSectors
	err := func() error {
		for _, action := range req.Actions {
			switch action.Type {
			case renterhost.RPCWriteActionAppend:
				if uint64(len(action.Data)) != renterhost.SectorSize {
					return errors.New("length of appended data must be exactly SectorSize")
				}
				newSectors++

			case renterhost.RPCWriteActionTrim:
				if action.A > newSectors {
					return errors.New("trim size exceeds number of sectors")
				}
				newSectors -= action.A

			case renterhost.RPCWriteActionSwap:
				i, j := action.A, action.B
				if i >= newSectors || j >= newSectors {
					return errors.New("swap index is out-of-bounds")
				}

			case renterhost.RPCWriteActionUpdate:
				sectorIndex, offset := action.A, action.B
				if sectorIndex >= newSectors {
					return errors.New("updated sector index is out-of-bounds")
				} else if offset+uint64(len(action.Data)) > renterhost.SectorSize {
					return errors.New("updated section is out-of-bounds")
				} else if req.MerkleProof && (offset%merkle.SegmentSize != 0 || len(action.Data)%merkle.SegmentSize != 0) {
					return errors.New("updated section must align to SegmentSize boundaries when requesting a Merkle proof")
				}

			default:
				return errors.New("unknown action type " + action.Type.String())
			}
		}
		return nil
	}()
	if err != nil {
		return s.writeError(err)
	}

	// compute new Merkle root (and proof, if requested)
	merkleResp, err := sm.storage.ConsiderModifications(s.contract.ID(), req.Actions, req.MerkleProof)
	if err != nil {
		return s.writeError(err)
	}

	// construct the new revision
	currentRevision := s.contract
	newRevision, err := calculateRevision(currentRevision, req.NewRevisionNumber, req.NewValidProofValues, req.NewMissedProofValues)
	if err != nil {
		return s.writeError(err)
	}
	for _, action := range req.Actions {
		if action.Type == renterhost.RPCWriteActionAppend {
			newRevision.NewFileSize += renterhost.SectorSize
		} else if action.Type == renterhost.RPCWriteActionTrim {
			newRevision.NewFileSize -= renterhost.SectorSize * action.A
		}
	}
	newRevision.NewFileMerkleRoot = merkleResp.NewMerkleRoot

	// verify revision
	var rc revisionCharges
	if newSectors > oldSectors {
		rc.Storage = renterhost.SectorSize * uint64(newSectors-oldSectors)
	}
	for _, action := range req.Actions {
		switch action.Type {
		case renterhost.RPCWriteActionAppend:
			rc.Up += renterhost.SectorSize
		case renterhost.RPCWriteActionUpdate:
			rc.Up += uint64(len(action.Data))
			// TODO: this should count as a sector access, but existing renters don't treat it as such
		}
	}
	if req.MerkleProof {
		rc.Down += crypto.HashSize * uint64(len(merkleResp.OldSubtreeHashes)+len(merkleResp.OldLeafHashes)+1)
	}
	if err := sm.contracts.ConsiderRevision(currentRevision, newRevision, rc, sm.settings.Settings(), sm.chain.CurrentHeight()); err != nil {
		return s.writeError(err)
	}

	// If a Merkle proof was requested, send it and wait for the renter's signature.
	if req.MerkleProof {
		if err := s.writeResponse(merkleResp); err != nil {
			return err
		} else if err := s.readResponse(&sigResponse); err != nil {
			return err
		}
	}

	// Apply the modifications and sign the revision.
	var resp renterhost.RPCWriteResponse
	if err := sm.storage.ApplyModifications(s.contract.ID(), req.Actions); err != nil {
		return s.writeError(err)
	} else if resp.Signature, err = sm.contracts.AcceptRevision(newRevision, sigResponse.Signature); err != nil {
		return s.writeError(err)
	} else if err := s.writeResponse(&resp); err != nil {
		return err
	}
	s.contract = newRevision
	return nil
}

func (sm *SessionManager) rpcSectorRoots(s *session) error {
	var req renterhost.RPCSectorRootsRequest
	if err := s.readRequest(&req); err != nil {
		return err
	}
	if err := s.haveContract(true); err != nil {
		return s.writeError(err)
	}

	// construct the new revision
	currentRevision := s.contract
	newRevision, err := calculateRevision(currentRevision, req.NewRevisionNumber, req.NewValidProofValues, req.NewMissedProofValues)
	if err != nil {
		return s.writeError(err)
	}
	proofSize := merkle.ProofSize(int(currentRevision.NewFileSize/renterhost.SectorSize), int(req.RootOffset), int(req.RootOffset+req.NumRoots))
	rc := revisionCharges{
		Down: (req.NumRoots + uint64(proofSize)) * crypto.HashSize,
	}
	if err := sm.contracts.ConsiderRevision(currentRevision, newRevision, rc, sm.settings.Settings(), sm.chain.CurrentHeight()); err != nil {
		return s.writeError(err)
	}

	resp, err := sm.storage.ReadSectors(s.contract.ID(), req.RootOffset, req.NumRoots)
	if err != nil {
		return s.writeError(err)
	}

	// commit the new revision
	resp.Signature, err = sm.contracts.AcceptRevision(newRevision, req.Signature)
	if err != nil {
		return s.writeError(err)
	} else if err := s.writeResponse(resp); err != nil {
		return err
	}
	s.contract = newRevision
	return nil
}

func (sm *SessionManager) rpcRead(s *session) error {
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

	if err := s.haveContract(true); err != nil {
		s.writeError(err)
		<-stopSignal
		return err
	}

	currentRevision := s.contract
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
	if err := sm.contracts.ConsiderRevision(currentRevision, newRevision, rc, sm.settings.Settings(), sm.chain.CurrentHeight()); err != nil {
		return s.writeError(err)
	}

	// commit the new revision
	hostSig, err := sm.contracts.AcceptRevision(newRevision, req.Signature)
	if err != nil {
		return s.writeError(err)
	}
	s.contract = newRevision

	// enter response loop
	for i, sec := range req.Sections {
		resp, err := sm.storage.ReadSection(sec, req.MerkleProof)
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

// NewSessionManager returns an initialized session manager.
func NewSessionManager(secretKey ed25519.PrivateKey, settings SettingsManager, contracts *ContractManager, storage *StorageManager, wallet *WalletManager, chain *ChainManager) *SessionManager {
	sm := &SessionManager{
		secretKey: secretKey,
		settings:  settings,
		contracts: contracts,
		storage:   storage,
		wallet:    wallet,
		chain:     chain,
	}
	sm.rpcs = map[renterhost.Specifier]func(*session) error{
		renterhost.RPCFormContractID:       sm.rpcFormContract,
		renterhost.RPCLockID:               sm.rpcLock,
		renterhost.RPCReadID:               sm.rpcRead,
		renterhost.RPCRenewClearContractID: sm.rpcRenewAndClearContract,
		renterhost.RPCSectorRootsID:        sm.rpcSectorRoots,
		renterhost.RPCSettingsID:           sm.rpcSettings,
		renterhost.RPCUnlockID:             sm.rpcUnlock,
		renterhost.RPCWriteID:              sm.rpcWrite,
	}
	return sm
}
