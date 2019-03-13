package proto

import (
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renterhost"
)

// RenewContract negotiates a new file contract and initial revision for data
// already stored with a host.
func RenewContract(w Wallet, tpool TransactionPool, contract ContractEditor, host hostdb.ScannedHost, renterPayout types.Currency, startHeight, endHeight types.BlockHeight) (ContractRevision, error) {
	s, err := NewUnlockedSession(host.NetAddress, host.PublicKey, 0)
	if err != nil {
		return ContractRevision{}, err
	}
	s.host = host
	defer s.Close()
	if err := s.Lock(contract); err != nil {
		return ContractRevision{}, err
	}
	return s.RenewContract(w, tpool, contract, renterPayout, startHeight, endHeight)
}

// RenewContract negotiates a new file contract and initial revision for data
// already stored with a host.
func (s *Session) RenewContract(w Wallet, tpool TransactionPool, contract ContractEditor, renterPayout types.Currency, startHeight, endHeight types.BlockHeight) (ContractRevision, error) {
	if endHeight < startHeight {
		return ContractRevision{}, errors.New("end height must be greater than start height")
	}
	// get two renter addresses: one for the renter refund output, one for the
	// change output
	refundAddr, err := w.NewWalletAddress()
	if err != nil {
		return ContractRevision{}, errors.Wrap(err, "could not get an address to use")
	}
	changeAddr, err := w.NewWalletAddress()
	if err != nil {
		return ContractRevision{}, errors.Wrap(err, "could not get an address to use")
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
	currentRevision := contract.Revision().Revision
	var basePrice, baseCollateral types.Currency
	if endHeight+s.host.WindowSize > currentRevision.NewWindowEnd {
		timeExtension := uint64((endHeight + s.host.WindowSize) - currentRevision.NewWindowEnd)
		basePrice = s.host.StoragePrice.Mul64(currentRevision.NewFileSize).Mul64(timeExtension)    // cost of data already covered by contract
		baseCollateral = s.host.Collateral.Mul64(currentRevision.NewFileSize).Mul64(timeExtension) // same but collateral
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
	// the renter is responsible for paying host.ContractPrice, the siafund
	// tax, and a transaction fee.
	_, maxFee, err := tpool.FeeEstimate()
	if err != nil {
		return ContractRevision{}, errors.Wrap(err, "could not estimate transaction fee")
	}
	fee := maxFee.Mul64(estTxnSize)
	totalCost := renterPayout.Add(s.host.ContractPrice).Add(types.Tax(startHeight, fc.Payout)).Add(fee)

	// create and fund a transaction containing fc
	txn := types.Transaction{
		FileContracts: []types.FileContract{fc},
		MinerFees:     []types.Currency{fee},
	}
	toSign, err := fundSiacoins(&txn, totalCost, changeAddr, w)
	if err != nil {
		return ContractRevision{}, err
	}

	s.extendDeadline(60 * time.Second)
	req := &renterhost.RPCFormContractRequest{
		Transactions: []types.Transaction{txn},
		RenterKey:    contract.Revision().Revision.UnlockConditions.PublicKeys[0],
	}
	if err := s.sess.WriteRequest(renterhost.RPCRenewContractID, req); err != nil {
		return ContractRevision{}, err
	}

	var resp renterhost.RPCFormContractAdditions
	if err := s.sess.ReadResponse(&resp, 4096); err != nil {
		return ContractRevision{}, err
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
		return ContractRevision{}, err
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
		Signature:      contract.Key().SignHash(crypto.HashObject(initRevision)),
	}

	// Send signatures.
	renterSigs := &renterhost.RPCFormContractSignatures{
		ContractSignatures: addedSignatures,
		RevisionSignature:  renterRevisionSig,
	}
	if err := s.sess.WriteResponse(renterSigs, nil); err != nil {
		return ContractRevision{}, err
	}

	// Read the host signatures.
	var hostSigs renterhost.RPCFormContractSignatures
	if err := s.sess.ReadResponse(&hostSigs, 4096); err != nil {
		return ContractRevision{}, err
	}
	txn.TransactionSignatures = append(txn.TransactionSignatures, hostSigs.ContractSignatures...)

	// submit contract txn to tpool
	signedTxnSet := append(resp.Parents, txn)
	err = tpool.AcceptTransactionSet(signedTxnSet)
	if err != nil && err != modules.ErrDuplicateTransactionSet {
		return ContractRevision{}, errors.Wrap(err, "contract transaction was not accepted")
	}

	return ContractRevision{
		Revision:   initRevision,
		Signatures: [2]types.TransactionSignature{renterRevisionSig, hostSigs.RevisionSignature},
	}, nil
}
