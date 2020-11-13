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
	// get a renter address for the file contract's valid/missed outputs
	refundAddr, err := w.Address()
	if err != nil {
		return ContractRevision{}, nil, errors.Wrap(err, "could not get an address to use")
	}

	// calculate "base" price and collateral -- the storage cost and collateral
	// contribution for the amount of data already in contract. If the contract
	// height did not increase, basePrice and baseCollateral are zero.
	currentRevision := s.rev.Revision
	var basePrice, baseCollateral types.Currency
	if contractEnd := endHeight + s.host.WindowSize; contractEnd > currentRevision.NewWindowEnd {
		timeExtension := uint64(contractEnd - currentRevision.NewWindowEnd)
		basePrice = s.host.StoragePrice.Mul64(currentRevision.NewFileSize).Mul64(timeExtension)
		baseCollateral = s.host.Collateral.Mul64(currentRevision.NewFileSize).Mul64(timeExtension)
	}

	// estimate collateral for new contract
	var newCollateral types.Currency
	if costPerByte := s.host.UploadBandwidthPrice.Add(s.host.StoragePrice).Add(s.host.DownloadBandwidthPrice); !costPerByte.IsZero() {
		bytes := renterPayout.Div(costPerByte)
		newCollateral = s.host.Collateral.Mul(bytes)
	}

	// the collateral can't be greater than MaxCollateral
	totalCollateral := baseCollateral.Add(newCollateral)
	if totalCollateral.Cmp(s.host.MaxCollateral) > 0 {
		totalCollateral = s.host.MaxCollateral
	}

	// Calculate payouts: the host gets their contract fee, plus the cost of the
	// data already in the contract, plus their collateral. In the event of a
	// missed payout, the cost and collateral of the data already in the
	// contract is subtracted from the host, and sent to the void instead.
	//
	// However, it is possible for this subtraction to underflow; this can
	// happen if baseCollateral is large and MaxCollateral is small. We cannot
	// simply replace the underflow with a zero, because the host performs the
	// same subtraction and returns an error on underflow. Nor can we increase
	// the valid payout, because the host calculates its collateral contribution
	// by subtracting the contract price and base price from this payout, and
	// we're already at MaxCollateral. Thus the host has conflicting
	// requirements, and renewing the contract is impossible until they change
	// their settings.
	hostValidPayout := s.host.ContractPrice.Add(basePrice).Add(totalCollateral)
	voidMissedPayout := basePrice.Add(baseCollateral)
	if hostValidPayout.Cmp(voidMissedPayout) < 0 {
		return ContractRevision{}, nil, errors.New("host's settings are unsatisfiable")
	}
	hostMissedPayout := hostValidPayout.Sub(voidMissedPayout)

	// create file contract
	fc := types.FileContract{
		FileSize:       currentRevision.NewFileSize,
		FileMerkleRoot: currentRevision.NewFileMerkleRoot,
		WindowStart:    endHeight,
		WindowEnd:      endHeight + s.host.WindowSize,
		Payout:         taxAdjustedPayout(renterPayout.Add(hostValidPayout)),
		UnlockHash:     currentRevision.NewUnlockHash,
		RevisionNumber: 0,
		ValidProofOutputs: []types.SiacoinOutput{
			{Value: renterPayout, UnlockHash: refundAddr},
			{Value: hostValidPayout, UnlockHash: s.host.UnlockHash},
		},
		MissedProofOutputs: []types.SiacoinOutput{
			{Value: renterPayout, UnlockHash: refundAddr},
			{Value: hostMissedPayout, UnlockHash: s.host.UnlockHash},
			{Value: voidMissedPayout, UnlockHash: types.UnlockHash{}},
		},
	}

	// Calculate how much the renter needs to pay. On top of the renterPayout,
	// the renter is responsible for paying host.ContractPrice, the base price,
	// the siafund tax, and a transaction fee. Or, more simply, the renter has
	// to pay for everything *except* the host's collateral contribution.
	_, maxFee, err := tpool.FeeEstimate()
	if err != nil {
		return ContractRevision{}, nil, errors.Wrap(err, "could not estimate transaction fee")
	}
	fee := maxFee.Mul64(estTxnSize)
	renterCost := fc.Payout.Sub(totalCollateral).Add(fee)

	// create and fund a transaction containing fc
	txn := types.Transaction{
		FileContracts: []types.FileContract{fc},
	}
	if !fee.IsZero() {
		txn.MinerFees = append(txn.MinerFees, fee)
	}
	toSign, discard, err := w.FundTransaction(&txn, renterCost)
	if err != nil {
		return ContractRevision{}, nil, err
	}
	defer discard()
	// the host expects the contract to have no TransactionSignatures
	addedSignatures := txn.TransactionSignatures
	txn.TransactionSignatures = nil

	// include any unconfirmed parent transactions
	parents, err := tpool.UnconfirmedParents(txn)
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
	txn.TransactionSignatures = addedSignatures
	err = w.SignTransaction(&txn, toSign)
	if err != nil {
		err = errors.Wrap(err, "failed to sign transaction")
		s.sess.WriteResponse(nil, err)
		return ContractRevision{}, nil, err
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
