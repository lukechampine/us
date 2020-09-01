package proto

import (
	"crypto/ed25519"
	"math"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/types"

	"lukechampine.com/us/ed25519hash"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renterhost"
)

// RenewContract negotiates a new file contract and initial revision for data
// already stored with a host.
func RenewContract(w Wallet, tpool TransactionPool, id types.FileContractID, key ed25519.PrivateKey, host hostdb.ScannedHost, renterPayout types.Currency, startHeight, endHeight types.BlockHeight) (ContractRevision, []types.Transaction, error) {
	s, err := NewUnlockedSession(host.NetAddress, host.PublicKey, 0)
	if err != nil {
		return ContractRevision{}, nil, err
	}
	s.host = host
	defer s.Close()
	if err := s.Lock(id, key, 10*time.Second); err != nil {
		return ContractRevision{}, nil, err
	}
	return s.RenewContract(w, tpool, renterPayout, startHeight, endHeight)
}

// RenewContract negotiates a new file contract and initial revision for data
// already stored with a host. The old contract is "cleared," reverting its
// filesize to zero.
func (s *Session) RenewContract(w Wallet, tpool TransactionPool, renterPayout types.Currency, startHeight, endHeight types.BlockHeight) (_ ContractRevision, _ []types.Transaction, err error) {
	defer wrapErr(&err, "RenewContract")
	if endHeight < startHeight {
		return ContractRevision{}, nil, errors.New("end height must be greater than start height")
	}
	// get two renter addresses: one for the renter refund output, one for the
	// change output
	refundAddr, err := w.NewWalletAddress()
	if err != nil {
		return ContractRevision{}, nil, errors.Wrap(err, "could not get an address to use")
	}
	changeAddr, err := w.NewWalletAddress()
	if err != nil {
		return ContractRevision{}, nil, errors.Wrap(err, "could not get an address to use")
	}

	// estimate collateral
	var hostCollateral types.Currency
	blockBytes := s.host.UploadBandwidthPrice.Add(s.host.StoragePrice).Add(s.host.DownloadBandwidthPrice).Mul64(uint64(endHeight - startHeight))
	if !blockBytes.IsZero() {
		bytes := renterPayout.Div(blockBytes)
		hostCollateral = s.host.Collateral.Mul(bytes).Mul64(uint64(endHeight - startHeight))
	}
	// hostCollateral can't be greater than MaxCollateral, and (due to a host-
	// side bug) it can't be zero either.
	if hostCollateral.Cmp(s.host.MaxCollateral) > 0 {
		hostCollateral = s.host.MaxCollateral
	} else if hostCollateral.IsZero() {
		hostCollateral = types.NewCurrency64(1)
	}

	// Calculate additional basePrice and baseCollateral. If the contract
	// height did not increase, basePrice and baseCollateral are zero.
	currentRevision := s.rev.Revision
	var basePrice, baseCollateral types.Currency
	if endHeight+s.host.WindowSize > currentRevision.NewWindowEnd {
		timeExtension := uint64((endHeight + s.host.WindowSize) - currentRevision.NewWindowEnd)
		basePrice = s.host.StoragePrice.Mul64(currentRevision.NewFileSize).Mul64(timeExtension)    // cost of data already covered by contract
		baseCollateral = s.host.Collateral.Mul64(currentRevision.NewFileSize).Mul64(timeExtension) // same but collateral
		// prevent underflow
		if baseCollateral.Cmp(hostCollateral) > 0 {
			baseCollateral = hostCollateral
		}
	}

	// calculate payouts
	hostPayout := s.host.ContractPrice.Add(hostCollateral).Add(basePrice)
	payout := taxAdjustedPayout(renterPayout.Add(hostPayout))

	// create file contract
	fc := types.FileContract{
		FileSize:       currentRevision.NewFileSize,
		FileMerkleRoot: currentRevision.NewFileMerkleRoot,
		WindowStart:    endHeight,
		WindowEnd:      endHeight + s.host.WindowSize,
		Payout:         payout,
		UnlockHash:     currentRevision.NewUnlockHash,
		RevisionNumber: 0,
		ValidProofOutputs: []types.SiacoinOutput{
			// renter
			{Value: renterPayout, UnlockHash: refundAddr},
			// host
			{Value: hostPayout, UnlockHash: s.host.UnlockHash},
		},
		MissedProofOutputs: []types.SiacoinOutput{
			// renter
			{Value: renterPayout, UnlockHash: refundAddr},
			// baseCollateral is not returned to host
			{Value: hostPayout.Sub(basePrice.Add(baseCollateral)), UnlockHash: s.host.UnlockHash},
			// void gets the spent storage fees, plus the collateral being risked
			{Value: basePrice.Add(baseCollateral), UnlockHash: types.UnlockHash{}},
		},
	}

	// Calculate how much the renter needs to pay. On top of the renterPayout,
	// the renter is responsible for paying host.ContractPrice, the siafund tax,
	// and a transaction fee. Or, more simply, the renter has to pay for
	// everything *except* the host's collateral contribution.
	_, maxFee, err := tpool.FeeEstimate()
	if err != nil {
		return ContractRevision{}, nil, errors.Wrap(err, "could not estimate transaction fee")
	}
	fee := maxFee.Mul64(estTxnSize)
	totalCost := fc.Payout.Sub(hostCollateral).Add(fee)

	// create and fund a transaction containing fc
	txn := types.Transaction{
		FileContracts: []types.FileContract{fc},
		MinerFees:     []types.Currency{fee},
	}
	toSign, err := fundSiacoins(&txn, totalCost, changeAddr, w)
	if err != nil {
		return ContractRevision{}, nil, err
	}

	// include any unconfirmed parent transactions
	parents, err := w.UnconfirmedParents(txn)
	if err != nil {
		return ContractRevision{}, nil, err
	}

	// construct the final revision of the old contract
	finalPayment := s.host.BaseRPCPrice
	if finalPayment.Cmp(currentRevision.ValidRenterPayout()) > 0 {
		finalPayment = currentRevision.ValidRenterPayout()
	}
	finalOldRevision := currentRevision
	newValid, _ := updateRevisionOutputs(&finalOldRevision, finalPayment, types.ZeroCurrency)
	finalOldRevision.NewMissedProofOutputs = finalOldRevision.NewValidProofOutputs
	finalOldRevision.NewFileSize = 0
	finalOldRevision.NewFileMerkleRoot = crypto.Hash{}
	finalOldRevision.NewRevisionNumber = math.MaxUint64

	s.extendDeadline(120 * time.Second)
	req := &renterhost.RPCRenewAndClearContractRequest{
		Transactions:           append(parents, txn),
		RenterKey:              s.rev.Revision.UnlockConditions.PublicKeys[0],
		FinalValidProofValues:  newValid,
		FinalMissedProofValues: newValid,
	}
	if err := s.sess.WriteRequest(renterhost.RPCRenewClearContractID, req); err != nil {
		return ContractRevision{}, nil, err
	}

	var resp renterhost.RPCFormContractAdditions
	if err := s.sess.ReadResponse(&resp, 65536); err != nil {
		return ContractRevision{}, nil, err
	}

	// merge host additions with txn
	txn.SiacoinInputs = append(txn.SiacoinInputs, resp.Inputs...)
	txn.SiacoinOutputs = append(txn.SiacoinOutputs, resp.Outputs...)

	// sign the txn
	for _, id := range toSign {
		txn.TransactionSignatures = append(txn.TransactionSignatures, types.TransactionSignature{
			ParentID:       id,
			PublicKeyIndex: 0,
			CoveredFields:  types.CoveredFields{WholeTransaction: true},
		})
	}
	err = w.SignTransaction(&txn, toSign)
	if err != nil {
		err = errors.Wrap(err, "failed to sign transaction")
		s.sess.WriteResponse(nil, err)
		return ContractRevision{}, nil, err
	}

	// calculate signatures added
	var addedSignatures []types.TransactionSignature
	for _, sig := range txn.TransactionSignatures {
		for _, id := range toSign {
			if id == sig.ParentID {
				addedSignatures = append(addedSignatures, sig)
				break
			}
		}
	}

	// create initial (no-op) revision, transaction, and signature
	initRevision := types.FileContractRevision{
		ParentID:          txn.FileContractID(0),
		UnlockConditions:  currentRevision.UnlockConditions,
		NewRevisionNumber: 1,

		NewFileSize:           fc.FileSize,
		NewFileMerkleRoot:     fc.FileMerkleRoot,
		NewWindowStart:        fc.WindowStart,
		NewWindowEnd:          fc.WindowEnd,
		NewValidProofOutputs:  fc.ValidProofOutputs,
		NewMissedProofOutputs: fc.MissedProofOutputs,
		NewUnlockHash:         fc.UnlockHash,
	}
	renterRevisionSig := types.TransactionSignature{
		ParentID:       crypto.Hash(initRevision.ParentID),
		CoveredFields:  types.CoveredFields{FileContractRevisions: []uint64{0}},
		PublicKeyIndex: 0,
		Signature:      ed25519hash.Sign(s.key, renterhost.HashRevision(initRevision)),
	}

	// Send signatures.
	renterSigs := &renterhost.RPCRenewAndClearContractSignatures{
		ContractSignatures:     addedSignatures,
		RevisionSignature:      renterRevisionSig,
		FinalRevisionSignature: ed25519hash.Sign(s.key, renterhost.HashRevision(finalOldRevision)),
	}
	if err := s.sess.WriteResponse(renterSigs, nil); err != nil {
		return ContractRevision{}, nil, err
	}

	// Read the host signatures.
	var hostSigs renterhost.RPCRenewAndClearContractSignatures
	if err := s.sess.ReadResponse(&hostSigs, 4096); err != nil {
		return ContractRevision{}, nil, err
	}
	txn.TransactionSignatures = append(txn.TransactionSignatures, hostSigs.ContractSignatures...)
	signedTxnSet := append(resp.Parents, append(parents, txn)...)

	return ContractRevision{
		Revision:   initRevision,
		Signatures: [2]types.TransactionSignature{renterRevisionSig, hostSigs.RevisionSignature},
	}, signedTxnSet, nil
}
