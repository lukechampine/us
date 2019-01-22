package proto

import (
	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/encoding"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/hostdb"
)

// RenewContract negotiates a new file contract and initial revision for data
// already stored with a host.
func RenewContract(w Wallet, tpool TransactionPool, contract ContractEditor, host hostdb.ScannedHost, renterPayout types.Currency, startHeight, endHeight types.BlockHeight) (ContractRevision, error) {
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
	blockBytes := host.UploadBandwidthPrice.Add(host.StoragePrice).Add(host.DownloadBandwidthPrice).Mul64(uint64(endHeight - startHeight))
	if !blockBytes.IsZero() {
		bytes := renterPayout.Div(blockBytes)
		hostCollateral = host.Collateral.Mul(bytes).Mul64(uint64(endHeight - startHeight))
	}
	// hostCollateral can't be greater than MaxCollateral, and (due to a host-
	// side bug) it can't be zero either.
	if hostCollateral.Cmp(host.MaxCollateral) > 0 {
		hostCollateral = host.MaxCollateral
	} else if hostCollateral.IsZero() {
		hostCollateral = types.NewCurrency64(1)
	}

	// Calculate additional basePrice and baseCollateral. If the contract
	// height did not increase, basePrice and baseCollateral are zero.
	currentRevision := contract.Revision().Revision
	var basePrice, baseCollateral types.Currency
	if endHeight+host.WindowSize > currentRevision.NewWindowEnd {
		timeExtension := uint64((endHeight + host.WindowSize) - currentRevision.NewWindowEnd)
		basePrice = host.StoragePrice.Mul64(currentRevision.NewFileSize).Mul64(timeExtension)    // cost of data already covered by contract
		baseCollateral = host.Collateral.Mul64(currentRevision.NewFileSize).Mul64(timeExtension) // same but collateral
	}

	// calculate payouts
	hostPayout := host.ContractPrice.Add(hostCollateral).Add(basePrice)
	payout := taxAdjustedPayout(renterPayout.Add(hostPayout))

	// create file contract
	fc := types.FileContract{
		FileSize:       currentRevision.NewFileSize,
		FileMerkleRoot: currentRevision.NewFileMerkleRoot,
		WindowStart:    endHeight,
		WindowEnd:      endHeight + host.WindowSize,
		Payout:         payout,
		UnlockHash:     currentRevision.NewUnlockHash,
		RevisionNumber: 0,
		ValidProofOutputs: []types.SiacoinOutput{
			// renter
			{Value: renterPayout, UnlockHash: refundAddr},
			// host
			{Value: hostPayout, UnlockHash: host.UnlockHash},
		},
		MissedProofOutputs: []types.SiacoinOutput{
			// renter
			{Value: renterPayout, UnlockHash: refundAddr},
			// baseCollateral is not returned to host
			{Value: hostPayout.Sub(basePrice.Add(baseCollateral)), UnlockHash: host.UnlockHash},
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
	totalCost := renterPayout.Add(host.ContractPrice).Add(types.Tax(startHeight, fc.Payout)).Add(fee)

	// create and fund a transaction containing fc
	txn := types.Transaction{
		FileContracts: []types.FileContract{fc},
		MinerFees:     []types.Currency{fee},
	}
	toSign, err := fundSiacoins(&txn, totalCost, changeAddr, w)
	if err != nil {
		return ContractRevision{}, err
	}

	// initiate connection
	conn, _, err := initiateRPC(host.NetAddress, modules.RPCRenewContract, contract)
	if err != nil {
		return ContractRevision{}, err
	}
	defer func() { _ = conn.Close() }()

	// verify the host's settings and confirm its identity
	host, err = verifySettings(conn, host)
	if err != nil {
		return ContractRevision{}, errors.Wrap(err, "settings exchange failed")
	}
	if !host.AcceptingContracts {
		return ContractRevision{}, errors.New("host is not accepting contracts")
	}

	// allot time for negotiation
	extendDeadline(conn, modules.NegotiateRenewContractTime)

	// send acceptance, txn signed by us, and pubkey
	if err = modules.WriteNegotiationAcceptance(conn); err != nil {
		return ContractRevision{}, errors.Wrap(err, "could not send initial acceptance")
	}
	if err = encoding.WriteObject(conn, []types.Transaction{txn}); err != nil {
		return ContractRevision{}, errors.Wrap(err, "could not send the contract signed by us")
	}
	ourPK := contract.Key().PublicKey().Key
	if err = encoding.WritePrefixedBytes(conn, ourPK); err != nil {
		return ContractRevision{}, errors.Wrap(err, "could not send our public key")
	}

	// read acceptance and txn signed by host
	if err = modules.ReadNegotiationAcceptance(conn); err != nil {
		return ContractRevision{}, errors.New("host did not accept our proposed contract: " + err.Error())
	}
	// host now sends any new parent transactions, inputs and outputs that
	// were added to the transaction
	var hostParents []types.Transaction
	var hostInputs []types.SiacoinInput
	var hostOutputs []types.SiacoinOutput
	if err = encoding.ReadObject(conn, &hostParents, types.BlockSizeLimit); err != nil {
		return ContractRevision{}, errors.Wrap(err, "could not read the host's added parents")
	}
	if err = encoding.ReadObject(conn, &hostInputs, types.BlockSizeLimit); err != nil {
		return ContractRevision{}, errors.Wrap(err, "could not read the host's added inputs")
	}
	if err = encoding.ReadObject(conn, &hostOutputs, types.BlockSizeLimit); err != nil {
		return ContractRevision{}, errors.Wrap(err, "could not read the host's added outputs")
	}

	// merge host additions with txn
	txn.SiacoinInputs = append(txn.SiacoinInputs, hostInputs...)
	txn.SiacoinOutputs = append(txn.SiacoinOutputs, hostOutputs...)

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
		modules.WriteNegotiationRejection(conn, err)
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
	renterRevisionSig := revisionSignature(initRevision, contract.Key())

	// Send acceptance and signatures
	if err = modules.WriteNegotiationAcceptance(conn); err != nil {
		return ContractRevision{}, errors.Wrap(err, "could not send transaction acceptance")
	}
	if err = encoding.WriteObject(conn, addedSignatures); err != nil {
		return ContractRevision{}, errors.Wrap(err, "could not send added signatures")
	}
	if err = encoding.WriteObject(conn, renterRevisionSig); err != nil {
		return ContractRevision{}, errors.Wrap(err, "could not send revision signature")
	}

	// Read the host acceptance and signatures.
	err = modules.ReadNegotiationAcceptance(conn)
	if err != nil {
		return ContractRevision{}, errors.Wrap(err, "host did not accept our signatures")
	}
	var hostSigs []types.TransactionSignature
	if err = encoding.ReadObject(conn, &hostSigs, 2e3); err != nil {
		return ContractRevision{}, errors.Wrap(err, "could not read the host's signatures")
	}
	txn.TransactionSignatures = append(txn.TransactionSignatures, hostSigs...)
	var hostRevisionSig types.TransactionSignature
	if err = encoding.ReadObject(conn, &hostRevisionSig, 2e3); err != nil {
		return ContractRevision{}, errors.Wrap(err, "could not read the host's revision signature")
	}

	// submit contract txn to tpool
	signedTxnSet := append(hostParents, txn)
	err = tpool.AcceptTransactionSet(signedTxnSet)
	if err != nil && err != modules.ErrDuplicateTransactionSet {
		return ContractRevision{}, errors.Wrap(err, "contract transaction was not accepted")
	}

	return ContractRevision{
		Revision:   initRevision,
		Signatures: [2]types.TransactionSignature{renterRevisionSig, hostRevisionSig},
	}, nil
}
