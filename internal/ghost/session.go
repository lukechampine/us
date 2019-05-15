package ghost

import (
	"encoding/json"
	"math/bits"
	"net"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/types"
	"gitlab.com/NebulousLabs/fastrand"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renterhost"
)

type session struct {
	sess     *renterhost.Session
	conn     net.Conn
	contract *hostContract
}

func (s *session) extendDeadline(d time.Duration) {
	_ = s.conn.SetDeadline(time.Now().Add(d))
}

func (h *Host) handleConn(conn net.Conn) error {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))

	// establish Session
	hs, err := renterhost.NewHostSession(conn, h.secretKey)
	if err != nil {
		return err
	}
	s := &session{
		sess: hs,
		conn: conn,
	}

	rpcs := map[renterhost.Specifier]func(*session) error{
		renterhost.RPCSettingsID:     h.rpcSettings,
		renterhost.RPCFormContractID: h.rpcFormContract,
		renterhost.RPCLockID:         h.rpcLock,
		renterhost.RPCUnlockID:       h.rpcUnlock,
		renterhost.RPCWriteID:        h.rpcWrite,
		renterhost.RPCSectorRootsID:  h.rpcSectorRoots,
		renterhost.RPCReadID:         h.rpcRead,
		// modules.RPCLoopRenewContract: h.managedRPCLoopRenewContract,
	}
	for {
		s.extendDeadline(time.Hour)
		id, err := s.sess.ReadID()
		if err == renterhost.ErrRenterClosed {
			return nil
		} else if err != nil {
			return errors.Wrap(err, "could not read RPC ID")
		}
		if rpcFn, ok := rpcs[id]; !ok {
			err = errors.Errorf("invalid or unknown RPC %q", id.String())
			s.sess.WriteResponse(nil, err) // best effort
			return err
		} else if err := rpcFn(s); err != nil {
			return errors.Wrapf(err, "RPC %q failed", id.String())
		}
	}
}

func (h *Host) rpcSettings(s *session) error {
	s.extendDeadline(60 * time.Second)
	settings, _ := json.Marshal(h.Settings())
	resp := &renterhost.RPCSettingsResponse{
		Settings: settings,
	}
	return s.sess.WriteResponse(resp, nil)
}

func (h *Host) rpcFormContract(s *session) error {
	s.extendDeadline(120 * time.Second)

	var req renterhost.RPCFormContractRequest
	if err := s.sess.ReadRequest(&req, 4096); err != nil {
		return err
	}
	if len(req.Transactions) == 0 {
		err := errors.New("transaction set is empty")
		s.sess.WriteResponse(nil, err)
		return err
	}
	txn := req.Transactions[len(req.Transactions)-1]
	if len(txn.FileContracts) == 0 {
		err := errors.New("transaction does not contain a file contract")
		s.sess.WriteResponse(nil, err)
		return err
	}
	fc := txn.FileContracts[0]

	resp := &renterhost.RPCFormContractAdditions{
		Parents: nil,
		Inputs:  nil,
		Outputs: nil,
	}
	if err := s.sess.WriteResponse(resp, nil); err != nil {
		return err
	}

	// create initial (no-op revision)
	initRevision := types.FileContractRevision{
		ParentID: txn.FileContractID(0),
		UnlockConditions: types.UnlockConditions{
			PublicKeys: []types.SiaPublicKey{
				req.RenterKey,
				h.PublicKey().SiaPublicKey(),
			},
			SignaturesRequired: 2,
		},
		NewRevisionNumber: 1,

		NewFileSize:           fc.FileSize,
		NewFileMerkleRoot:     fc.FileMerkleRoot,
		NewWindowStart:        fc.WindowStart,
		NewWindowEnd:          fc.WindowEnd,
		NewValidProofOutputs:  fc.ValidProofOutputs,
		NewMissedProofOutputs: fc.MissedProofOutputs,
		NewUnlockHash:         fc.UnlockHash,
	}
	hostRevisionSig := types.TransactionSignature{
		ParentID:       crypto.Hash(initRevision.ParentID),
		CoveredFields:  types.CoveredFields{FileContractRevisions: []uint64{0}},
		PublicKeyIndex: 1,
		Signature:      h.secretKey.SignHash(crypto.HashObject(initRevision)),
	}

	var renterSigs renterhost.RPCFormContractSignatures
	if err := s.sess.ReadResponse(&renterSigs, 4096); err != nil {
		return err
	}

	h.contracts[initRevision.ParentID] = &hostContract{
		rev: initRevision,
		sigs: [2]types.TransactionSignature{
			renterSigs.RevisionSignature,
			hostRevisionSig,
		},
		renterKey:  req.RenterKey,
		sectorData: make(map[crypto.Hash][renterhost.SectorSize]byte),
	}

	hostSigs := &renterhost.RPCFormContractSignatures{
		ContractSignatures: nil,
		RevisionSignature:  hostRevisionSig,
	}
	if err := s.sess.WriteResponse(hostSigs, nil); err != nil {
		return err
	}
	return nil
}

func (h *Host) rpcLock(s *session) error {
	s.extendDeadline(60 * time.Second)

	var req renterhost.RPCLockRequest
	if err := s.sess.ReadRequest(&req, 4096); err != nil {
		return err
	}

	if s.contract != nil {
		err := errors.New("another contract is already locked")
		s.sess.WriteResponse(nil, err)
		return err
	}

	contract, ok := h.contracts[req.ContractID]
	if !ok || !s.sess.VerifyChallenge(req.Signature, hostdb.HostPublicKey(contract.renterKey.String())) {
		err := errors.New("bad signature or no such contract")
		s.sess.WriteResponse(nil, err)
		return err
	}
	s.contract = contract

	var newChallenge [16]byte
	fastrand.Read(newChallenge[:])
	s.sess.SetChallenge(newChallenge)
	resp := &renterhost.RPCLockResponse{
		Acquired:     true,
		NewChallenge: newChallenge,
		Revision:     contract.rev,
		Signatures:   contract.sigs[:],
	}
	return s.sess.WriteResponse(resp, nil)
}

func (h *Host) rpcUnlock(s *session) error {
	s.contract = nil
	return nil
}

func (h *Host) rpcWrite(s *session) error {
	s.extendDeadline(120 * time.Second)
	var req renterhost.RPCWriteRequest
	if err := s.sess.ReadRequest(&req, renterhost.SectorSize*5); err != nil {
		return err
	}
	// if no Merkle proof was requested, the renter's signature should be sent
	// immediately
	var sigResponse renterhost.RPCWriteResponse
	if !req.MerkleProof {
		if err := s.sess.ReadResponse(&sigResponse, 4096); err != nil {
			return err
		}
	}

	if s.contract == nil {
		err := errors.New("no contract locked")
		s.sess.WriteResponse(nil, err)
		return err
	}

	settings := h.Settings()
	newRoots := append([]crypto.Hash(nil), s.contract.sectorRoots...)
	sectorsChanged := make(map[uint64]struct{})
	var bandwidthRevenue types.Currency
	var sectorsRemoved []crypto.Hash
	var sectorsGained []crypto.Hash
	gainedSectorData := make(map[crypto.Hash][renterhost.SectorSize]byte)
	for _, action := range req.Actions {
		switch action.Type {
		case renterhost.RPCWriteActionAppend:
			if uint64(len(action.Data)) != renterhost.SectorSize {
				err := errors.New("invalid sector size")
				s.sess.WriteResponse(nil, err)
				return err
			}
			var sector [renterhost.SectorSize]byte
			copy(sector[:], action.Data)
			newRoot := merkle.SectorRoot(&sector)
			newRoots = append(newRoots, newRoot)
			sectorsGained = append(sectorsGained, newRoot)
			gainedSectorData[newRoot] = sector

			sectorsChanged[uint64(len(newRoots))-1] = struct{}{}

			bandwidthRevenue = bandwidthRevenue.Add(settings.UploadBandwidthPrice.Mul64(renterhost.SectorSize))

		case renterhost.RPCWriteActionTrim:
			numSectors := action.A
			if uint64(len(newRoots)) < numSectors {
				err := errors.New("trim size exceeds number of sectors")
				s.sess.WriteResponse(nil, err)
				return err
			}
			sectorsRemoved = append(sectorsRemoved, newRoots[uint64(len(newRoots))-numSectors:]...)
			newRoots = newRoots[:uint64(len(newRoots))-numSectors]

			sectorsChanged[uint64(len(newRoots))] = struct{}{}

		case renterhost.RPCWriteActionSwap:
			i, j := action.A, action.B
			if i >= uint64(len(newRoots)) || j >= uint64(len(newRoots)) {
				err := errors.New("illegal sector index")
				s.sess.WriteResponse(nil, err)
				return err
			}
			newRoots[i], newRoots[j] = newRoots[j], newRoots[i]

			sectorsChanged[i] = struct{}{}
			sectorsChanged[j] = struct{}{}

		case renterhost.RPCWriteActionUpdate:
			sectorIndex, offset := action.A, action.B
			if sectorIndex >= uint64(len(newRoots)) {
				err := errors.New("illegal sector index or offset")
				s.sess.WriteResponse(nil, err)
				return err
			} else if offset+uint64(len(action.Data)) > renterhost.SectorSize {
				err := errors.New("illegal offset or length")
				s.sess.WriteResponse(nil, err)
				return err
			}
			sector := s.contract.sectorData[newRoots[sectorIndex]]
			copy(sector[offset:], action.Data)
			newRoot := merkle.SectorRoot(&sector)
			sectorsRemoved = append(sectorsRemoved, newRoots[sectorIndex])
			sectorsGained = append(sectorsGained, newRoot)
			gainedSectorData[newRoot] = sector
			newRoots[sectorIndex] = newRoot

			bandwidthRevenue = bandwidthRevenue.Add(settings.UploadBandwidthPrice.Mul64(uint64(len(action.Data))))

		default:
			err := errors.New("unknown action type " + action.Type.String())
			s.sess.WriteResponse(nil, err)
			return err
		}
	}

	var storageRevenue, newCollateral types.Currency
	if len(newRoots) > len(s.contract.sectorRoots) {
		bytesAdded := renterhost.SectorSize * uint64(len(newRoots)-len(s.contract.sectorRoots))
		blocksRemaining := s.contract.proofDeadline - h.blockHeight
		blockBytesCurrency := types.NewCurrency64(uint64(blocksRemaining)).Mul64(bytesAdded)
		storageRevenue = settings.StoragePrice.Mul(blockBytesCurrency)
		newCollateral = newCollateral.Add(settings.Collateral.Mul(blockBytesCurrency))
	}

	newMerkleRoot := merkle.MetaRoot(newRoots)
	var merkleResp *renterhost.RPCWriteMerkleProof
	if req.MerkleProof {
		treeHashes, leafHashes := merkle.BuildDiffProof(req.Actions, s.contract.sectorRoots)
		merkleResp = &renterhost.RPCWriteMerkleProof{
			OldSubtreeHashes: treeHashes,
			OldLeafHashes:    leafHashes,
			NewMerkleRoot:    newMerkleRoot,
		}
		proofSize := crypto.HashSize * (len(merkleResp.OldSubtreeHashes) + len(leafHashes) + 1)
		if proofSize < renterhost.MinMessageSize {
			proofSize = renterhost.MinMessageSize
		}
		bandwidthRevenue = bandwidthRevenue.Add(settings.DownloadBandwidthPrice.Mul64(uint64(proofSize)))
	}

	// construct the new revision
	currentRevision := s.contract.rev
	newRevision := currentRevision
	newRevision.NewRevisionNumber = req.NewRevisionNumber
	for _, action := range req.Actions {
		if action.Type == renterhost.RPCWriteActionAppend {
			newRevision.NewFileSize += renterhost.SectorSize
		} else if action.Type == renterhost.RPCWriteActionTrim {
			newRevision.NewFileSize -= renterhost.SectorSize * action.A
		}
	}
	newRevision.NewFileMerkleRoot = newMerkleRoot
	newRevision.NewValidProofOutputs = make([]types.SiacoinOutput, len(currentRevision.NewValidProofOutputs))
	for i := range newRevision.NewValidProofOutputs {
		newRevision.NewValidProofOutputs[i] = types.SiacoinOutput{
			Value:      req.NewValidProofValues[i],
			UnlockHash: currentRevision.NewValidProofOutputs[i].UnlockHash,
		}
	}
	newRevision.NewMissedProofOutputs = make([]types.SiacoinOutput, len(currentRevision.NewMissedProofOutputs))
	for i := range newRevision.NewMissedProofOutputs {
		newRevision.NewMissedProofOutputs[i] = types.SiacoinOutput{
			Value:      req.NewMissedProofValues[i],
			UnlockHash: currentRevision.NewMissedProofOutputs[i].UnlockHash,
		}
	}

	newRevenue := settings.BaseRPCPrice.Add(storageRevenue).Add(bandwidthRevenue)
	_ = newRevenue // TODO: verify revision

	// If a Merkle proof was requested, send it and wait for the renter's signature.
	if req.MerkleProof {
		if err := s.sess.WriteResponse(merkleResp, nil); err != nil {
			return err
		} else if err := s.sess.ReadResponse(&sigResponse, 4096); err != nil {
			return err
		}
	}

	s.contract.sectorRoots = newRoots
	for root, sector := range gainedSectorData {
		s.contract.sectorData[root] = sector
	}
	s.contract.rev = newRevision
	s.contract.sigs[0].Signature = sigResponse.Signature
	s.contract.sigs[1].Signature = h.secretKey.SignHash(crypto.HashObject(newRevision))

	resp := &renterhost.RPCWriteResponse{
		Signature: s.contract.sigs[1].Signature,
	}
	if err := s.sess.WriteResponse(resp, nil); err != nil {
		return err
	}
	return nil
}

func (h *Host) rpcSectorRoots(s *session) error {
	s.extendDeadline(120 * time.Second)

	var req renterhost.RPCSectorRootsRequest
	if err := s.sess.ReadRequest(&req, 4096); err != nil {
		return err
	}

	if s.contract == nil {
		err := errors.New("no contract locked")
		s.sess.WriteResponse(nil, err)
		return err
	}

	settings := h.Settings()
	currentRevision := s.contract.rev

	var err error
	if req.RootOffset > uint64(len(s.contract.sectorRoots)) || req.RootOffset+req.NumRoots > uint64(len(s.contract.sectorRoots)) {
		err = errors.New("request is out-of-bounds")
	} else if len(req.NewValidProofValues) != len(currentRevision.NewValidProofOutputs) {
		err = errors.New("wrong number of valid proof values")
	} else if len(req.NewMissedProofValues) != len(currentRevision.NewMissedProofOutputs) {
		err = errors.New("wrong number of missed proof values")
	}
	if err != nil {
		s.sess.WriteResponse(nil, err)
		return err
	}

	contractRoots := s.contract.sectorRoots[req.RootOffset:][:req.NumRoots]
	proofStart := int(req.RootOffset)
	proofEnd := int(req.RootOffset + req.NumRoots)
	proof := merkle.BuildSectorRangeProof(s.contract.sectorRoots, proofStart, proofEnd)

	// construct the new revision
	newRevision := currentRevision
	newRevision.NewRevisionNumber = req.NewRevisionNumber
	newRevision.NewValidProofOutputs = make([]types.SiacoinOutput, len(currentRevision.NewValidProofOutputs))
	for i := range newRevision.NewValidProofOutputs {
		newRevision.NewValidProofOutputs[i] = types.SiacoinOutput{
			Value:      req.NewValidProofValues[i],
			UnlockHash: currentRevision.NewValidProofOutputs[i].UnlockHash,
		}
	}
	newRevision.NewMissedProofOutputs = make([]types.SiacoinOutput, len(currentRevision.NewMissedProofOutputs))
	for i := range newRevision.NewMissedProofOutputs {
		newRevision.NewMissedProofOutputs[i] = types.SiacoinOutput{
			Value:      req.NewMissedProofValues[i],
			UnlockHash: currentRevision.NewMissedProofOutputs[i].UnlockHash,
		}
	}

	// calculate expected cost and verify against renter's revision
	responseSize := (req.NumRoots + uint64(len(proof))) * crypto.HashSize
	if responseSize < renterhost.MinMessageSize {
		responseSize = renterhost.MinMessageSize
	}
	bandwidthCost := settings.DownloadBandwidthPrice.Mul64(responseSize)
	totalCost := settings.BaseRPCPrice.Add(bandwidthCost)
	_ = totalCost // TODO: validate revision

	// commit the new revision
	s.contract.rev = newRevision
	s.contract.sigs[0].Signature = req.Signature
	s.contract.sigs[1].Signature = h.secretKey.SignHash(crypto.HashObject(newRevision))

	// send the response
	resp := &renterhost.RPCSectorRootsResponse{
		Signature:   s.contract.sigs[1].Signature,
		SectorRoots: contractRoots,
		MerkleProof: proof,
	}
	if err := s.sess.WriteResponse(resp, nil); err != nil {
		return err
	}
	return nil
}

func (h *Host) rpcRead(s *session) error {
	s.extendDeadline(120 * time.Second)

	var req renterhost.RPCReadRequest
	if err := s.sess.ReadRequest(&req, 4096); err != nil {
		return err
	}

	// As soon as we finish reading the request, we must begin listening for
	// RPCLoopReadStop, which may arrive at any time, and must arrive before the
	// RPC is considered complete.
	stopSignal := make(chan error, 1)
	go func() {
		var id renterhost.Specifier
		err := s.sess.ReadResponse(&id, 4096)
		if err != nil {
			stopSignal <- err
		} else if id != renterhost.RPCReadStop {
			stopSignal <- errors.New("expected 'stop' from renter, got " + id.String())
		} else {
			stopSignal <- nil
		}
	}()

	if s.contract == nil {
		err := errors.New("no contract locked")
		s.sess.WriteResponse(nil, err)
		<-stopSignal
		return err
	}

	settings := h.Settings()
	currentRevision := s.contract.rev

	for _, sec := range req.Sections {
		var err error
		switch {
		case uint64(sec.Offset)+uint64(sec.Length) > renterhost.SectorSize:
			err = errors.New("request is out-of-bounds")
		case sec.Length == 0:
			err = errors.New("length cannot be zero")
		case req.MerkleProof && (sec.Offset%merkle.SegmentSize != 0 || sec.Length%merkle.SegmentSize != 0):
			err = errors.New("offset and length must be multiples of SegmentSize when requesting a Merkle proof")
		case len(req.NewValidProofValues) != len(currentRevision.NewValidProofOutputs):
			err = errors.New("wrong number of valid proof values")
		case len(req.NewMissedProofValues) != len(currentRevision.NewMissedProofOutputs):
			err = errors.New("wrong number of missed proof values")
		}
		if err != nil {
			s.sess.WriteResponse(nil, err)
			return err
		}
	}

	// construct the new revision
	newRevision := currentRevision
	newRevision.NewRevisionNumber = req.NewRevisionNumber
	newRevision.NewValidProofOutputs = make([]types.SiacoinOutput, len(currentRevision.NewValidProofOutputs))
	for i := range newRevision.NewValidProofOutputs {
		newRevision.NewValidProofOutputs[i] = types.SiacoinOutput{
			Value:      req.NewValidProofValues[i],
			UnlockHash: currentRevision.NewValidProofOutputs[i].UnlockHash,
		}
	}
	newRevision.NewMissedProofOutputs = make([]types.SiacoinOutput, len(currentRevision.NewMissedProofOutputs))
	for i := range newRevision.NewMissedProofOutputs {
		newRevision.NewMissedProofOutputs[i] = types.SiacoinOutput{
			Value:      req.NewMissedProofValues[i],
			UnlockHash: currentRevision.NewMissedProofOutputs[i].UnlockHash,
		}
	}

	// calculate expected cost and verify against renter's revision
	var estBandwidth uint64
	sectorAccesses := make(map[crypto.Hash]struct{})
	for _, sec := range req.Sections {
		// use the worst-case proof size of 2*tree depth (this occurs when
		// proving across the two leaves in the center of the tree)
		estHashesPerProof := 2 * bits.Len64(renterhost.SectorSize/merkle.SegmentSize)
		estBandwidth += uint64(sec.Length) + uint64(estHashesPerProof*crypto.HashSize)
		sectorAccesses[sec.MerkleRoot] = struct{}{}
	}
	if estBandwidth < renterhost.MinMessageSize {
		estBandwidth = renterhost.MinMessageSize
	}
	bandwidthCost := settings.DownloadBandwidthPrice.Mul64(estBandwidth)
	sectorAccessCost := settings.SectorAccessPrice.Mul64(uint64(len(sectorAccesses)))
	totalCost := settings.BaseRPCPrice.Add(bandwidthCost).Add(sectorAccessCost)
	_ = totalCost // TODO: validate revision

	// commit the new revision
	hostSig := h.secretKey.SignHash(crypto.HashObject(newRevision))
	s.contract.rev = newRevision
	s.contract.sigs[0].Signature = req.Signature
	s.contract.sigs[1].Signature = hostSig

	// enter response loop
	for i, sec := range req.Sections {
		sector, ok := s.contract.sectorData[sec.MerkleRoot]
		if !ok {
			err := errors.Errorf("no sector with Merkle root %v", sec.MerkleRoot)
			s.sess.WriteResponse(nil, err)
			return err
		}
		data := sector[sec.Offset : sec.Offset+sec.Length]

		var proof []crypto.Hash
		if req.MerkleProof {
			proofStart := int(sec.Offset) / merkle.SegmentSize
			proofEnd := int(sec.Offset+sec.Length) / merkle.SegmentSize
			proof = merkle.BuildProof(&sector, proofStart, proofEnd, nil)
		}

		// Send the response. If the renter sent a stop signal, or this is the
		// final response, include our signature in the response.
		resp := &renterhost.RPCReadResponse{
			Signature:   nil,
			Data:        data,
			MerkleProof: proof,
		}
		select {
		case err := <-stopSignal:
			if err != nil {
				return err
			}
			resp.Signature = hostSig
			return s.sess.WriteResponse(resp, nil)
		default:
		}
		if i == len(req.Sections)-1 {
			resp.Signature = hostSig
		}
		if err := s.sess.WriteResponse(resp, nil); err != nil {
			return err
		}
	}
	// The stop signal must arrive before RPC is complete.
	return <-stopSignal
}
