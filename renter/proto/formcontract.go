package proto

import (
	"net"
	"sort"
	"time"

	"github.com/NebulousLabs/Sia/crypto"
	"github.com/NebulousLabs/Sia/encoding"
	"github.com/NebulousLabs/Sia/modules"
	"github.com/NebulousLabs/Sia/types"
	"github.com/pkg/errors"
	"lukechampine.com/us/hostdb"
)

const (
	// estTxnSize is the estimated size of an encoded file contract
	// transaction set.
	estTxnSize = 2048
)

// FormContract forms a contract with a host. The resulting contract will have
// renterPayout coins in the renter output.
func FormContract(w Wallet, tpool TransactionPool, host hostdb.ScannedHost, renterPayout types.Currency, startHeight, endHeight types.BlockHeight) (ContractTransaction, error) {
	if endHeight < startHeight {
		return ContractTransaction{}, errors.New("end height must be greater than start height")
	}
	// get two renter addresses: one for the renter refund output, one for the
	// change output
	refundAddr, err := w.NewWalletAddress()
	if err != nil {
		return ContractTransaction{}, errors.Wrap(err, "could not get an address to use")
	}
	changeAddr, err := w.NewWalletAddress()
	if err != nil {
		return ContractTransaction{}, errors.Wrap(err, "could not get an address to use")
	}

	// create our key
	ourSK, ourPK := crypto.GenerateKeyPair()
	ourPublicKey := types.Ed25519PublicKey(ourPK)

	// create unlock conditions
	uc := types.UnlockConditions{
		PublicKeys:         []types.SiaPublicKey{ourPublicKey, host.PublicKey.SiaPublicKey()},
		SignaturesRequired: 2,
	}

	// estimate filesize. The filesize will be used to calculate collateral.
	// Note that it's okay to estimate the collateral: the host only cares if
	// we exceed MaxCollateral, and we only care about the tax we pay on it.
	var hostCollateral types.Currency
	blockBytes := host.UploadBandwidthPrice.Add(host.StoragePrice).Add(host.DownloadBandwidthPrice).Mul64(uint64(endHeight - startHeight))
	if !blockBytes.IsZero() {
		bytes := renterPayout.Div(blockBytes)
		hostCollateral := host.Collateral.Mul(bytes).Mul64(uint64(endHeight - startHeight))
		if hostCollateral.Cmp(host.MaxCollateral) > 0 {
			hostCollateral = host.MaxCollateral
		}
	}

	// calculate payouts
	//
	// NOTE: due to a bug in the transaction validation code, tax is
	// calculated on the post-tax contract payout (instead of the sum of the
	// renter and host payouts). So the equation for the payout is:
	//
	//   payout - tax*payout = hostPayout + renterPayout
	//             ∴  payout = (hostPayout + renterPayout) / 1-tax
	//
	// However, even this is not sufficient, because 'tax' is not a simple
	// fraction, but a function that rounds down to the nearest multiple of
	// the siafund count. Therefore, we are forced to first estimate the
	// payout, then subtract the tax from it, and finally adjust the host and
	// renter payouts to sum to that number. Fortunately, we have some room to
	// tweak the host payout because collateral values are not expected to be
	// exact. But because we may already be using the maximum accepted
	// collateral, we cannot add to the hostPayout. Instead, we intentionally
	// underestimate the total payout.
	hostPayout := host.ContractPrice.Add(hostCollateral)
	outputSum := hostPayout.Add(renterPayout)
	payout := outputSum.Mul64(1000).Div64(960) // should be 961

	// adjust the hostPayout
	hostPayout = types.PostTax(startHeight, payout).Sub(renterPayout)

	// create file contract
	fc := types.FileContract{
		FileSize:       0,
		FileMerkleRoot: crypto.Hash{}, // no proof possible without data
		WindowStart:    endHeight,
		WindowEnd:      endHeight + host.WindowSize,
		Payout:         payout,
		UnlockHash:     uc.UnlockHash(),
		RevisionNumber: 0,
		ValidProofOutputs: []types.SiacoinOutput{
			// outputs need to account for tax
			{Value: renterPayout, UnlockHash: refundAddr},
			// collateral is returned to host
			{Value: hostPayout, UnlockHash: host.UnlockHash},
		},
		MissedProofOutputs: []types.SiacoinOutput{
			// same as above
			{Value: renterPayout, UnlockHash: refundAddr},
			// same as above
			{Value: hostPayout, UnlockHash: host.UnlockHash},
			// once we start doing revisions, we'll move some coins to the host and some to the void
			{Value: types.ZeroCurrency, UnlockHash: types.UnlockHash{}},
		},
	}

	// Calculate how much the renter needs to pay. On top of the renterPayout,
	// the renter is responsible for paying host.ContractPrice, the siafund
	// tax, and a transaction fee.
	_, maxFee := tpool.FeeEstimate()
	fee := maxFee.Mul64(estTxnSize)
	totalCost := renterPayout.Add(host.ContractPrice).Add(types.Tax(startHeight, payout)).Add(fee)

	// create and fund a transaction containing fc
	txn := types.Transaction{
		FileContracts: []types.FileContract{fc},
		MinerFees:     []types.Currency{fee},
	}
	toSign, ok := fundSiacoins(&txn, w.SpendableOutputs(), totalCost, changeAddr)
	if !ok {
		return ContractTransaction{}, errors.New("not enough coins to fund contract transaction")
	}

	// initiate connection
	conn, err := net.DialTimeout("tcp", string(host.NetAddress), 15*time.Second)
	if err != nil {
		return ContractTransaction{}, errors.Wrap(err, "could not connect to host")
	}
	defer func() { _ = conn.Close() }()

	// allot time for sending RPC ID + verifySettings
	extendDeadline(conn, modules.NegotiateSettingsTime)
	if err = encoding.WriteObject(conn, modules.RPCFormContract); err != nil {
		return ContractTransaction{}, errors.Wrap(err, "could not write RPC header")
	}

	// verify the host's settings and confirm its identity
	host, err = verifySettings(conn, host)
	if err != nil {
		return ContractTransaction{}, errors.Wrap(err, "could not verify host settings")
	}
	if !host.AcceptingContracts {
		return ContractTransaction{}, errors.New("host is not accepting contracts")
	}

	// allot time for negotiation
	extendDeadline(conn, modules.NegotiateFileContractTime)

	// send acceptance of settings, unsigned txn containing contract, and pubkey
	if err = modules.WriteNegotiationAcceptance(conn); err != nil {
		return ContractTransaction{}, errors.Wrap(err, "could not send initial acceptance")
	}
	if err = encoding.WriteObject(conn, []types.Transaction{txn}); err != nil {
		return ContractTransaction{}, errors.Wrap(err, "could not send the contract signed by us")
	}
	if err = encoding.WriteObject(conn, ourSK.PublicKey()); err != nil {
		return ContractTransaction{}, errors.Wrap(err, "could not send our public key")
	}

	// read acceptance and txn signed by host
	if err = modules.ReadNegotiationAcceptance(conn); err != nil {
		return ContractTransaction{}, errors.Wrap(err, "host did not accept our proposed contract")
	}
	// host now sends any new parent transactions, inputs, and outputs that
	// were added to the transaction
	var hostParents []types.Transaction
	var hostInputs []types.SiacoinInput
	var hostOutputs []types.SiacoinOutput
	if err = encoding.ReadObject(conn, &hostParents, types.BlockSizeLimit); err != nil {
		return ContractTransaction{}, errors.Wrap(err, "could not read the host's added parents")
	}
	if err = encoding.ReadObject(conn, &hostInputs, types.BlockSizeLimit); err != nil {
		return ContractTransaction{}, errors.Wrap(err, "could not read the host's added inputs")
	}
	if err = encoding.ReadObject(conn, &hostOutputs, types.BlockSizeLimit); err != nil {
		return ContractTransaction{}, errors.Wrap(err, "could not read the host's added outputs")
	}

	// merge host additions with txn
	txn.SiacoinInputs = append(txn.SiacoinInputs, hostInputs...)
	txn.SiacoinOutputs = append(txn.SiacoinOutputs, hostOutputs...)

	// sign the txn
	err = w.SignTransaction(&txn, toSign)
	if err != nil {
		err = errors.Wrap(err, "failed to sign transaction")
		modules.WriteNegotiationRejection(conn, err)
		return ContractTransaction{}, err
	}

	// calculate signatures added
	var addedSignatures []types.TransactionSignature
	for _, sig := range txn.TransactionSignatures {
		if _, ok := toSign[types.OutputID(sig.ParentID)]; ok {
			addedSignatures = append(addedSignatures, sig)
		}
	}

	// create initial (no-op) revision, transaction, and signature
	initRevision := types.FileContractRevision{
		ParentID:          txn.FileContractID(0),
		UnlockConditions:  uc,
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
		PublicKeyIndex: 0,
		CoveredFields: types.CoveredFields{
			FileContractRevisions: []uint64{0},
		},
	}
	revisionTxn := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{initRevision},
		TransactionSignatures: []types.TransactionSignature{renterRevisionSig},
	}
	encodedSig := crypto.SignHash(revisionTxn.SigHash(0), ourSK)
	revisionTxn.TransactionSignatures[0].Signature = encodedSig[:]

	// Send acceptance and signatures
	if err = modules.WriteNegotiationAcceptance(conn); err != nil {
		return ContractTransaction{}, errors.Wrap(err, "could not send transaction acceptance")
	}
	if err = encoding.WriteObject(conn, addedSignatures); err != nil {
		return ContractTransaction{}, errors.Wrap(err, "could not send added signatures")
	}
	if err = encoding.WriteObject(conn, revisionTxn.TransactionSignatures[0]); err != nil {
		return ContractTransaction{}, errors.Wrap(err, "could not send revision signature")
	}

	// Read the host acceptance and signatures.
	err = modules.ReadNegotiationAcceptance(conn)
	if err != nil {
		return ContractTransaction{}, errors.Wrap(err, "host did not accept our signatures")
	}
	var hostSigs []types.TransactionSignature
	if err = encoding.ReadObject(conn, &hostSigs, 2e3); err != nil {
		return ContractTransaction{}, errors.Wrap(err, "could not read the host's signatures")
	}
	txn.TransactionSignatures = append(txn.TransactionSignatures, hostSigs...)
	var hostRevisionSig types.TransactionSignature
	if err = encoding.ReadObject(conn, &hostRevisionSig, 2e3); err != nil {
		return ContractTransaction{}, errors.Wrap(err, "could not read the host's revision signature")
	}
	revisionTxn.TransactionSignatures = append(revisionTxn.TransactionSignatures, hostRevisionSig)

	// submit contract txn to tpool
	signedTxnSet := append(hostParents, txn)
	err = tpool.AcceptTransactionSet(signedTxnSet)
	if err != nil && err != modules.ErrDuplicateTransactionSet {
		return ContractTransaction{}, errors.Wrap(err, "contract transaction was not accepted")
	}

	return ContractTransaction{
		Transaction: revisionTxn,
		RenterKey:   ourSK,
	}, nil
}

func fundSiacoins(txn *types.Transaction, outputs []modules.SpendableOutput, amount types.Currency, changeAddr types.UnlockHash) (map[types.OutputID]types.UnlockHash, bool) {
	// sort outputs by value, high to low
	sort.Slice(outputs, func(i, j int) bool {
		return outputs[i].Value.Cmp(outputs[j].Value) > 0
	})

	// keep adding outputs until we have enough
	var fundingOutputs []modules.SpendableOutput
	var outputSum types.Currency
	for i, o := range outputs {
		if o.FundType != types.SpecifierSiacoinOutput {
			continue
		}
		if outputSum = outputSum.Add(o.Value); outputSum.Cmp(amount) >= 0 {
			fundingOutputs = outputs[:i+1]
			break
		}
	}
	if outputSum.Cmp(amount) < 0 {
		return nil, false
	}

	toSign := make(map[types.OutputID]types.UnlockHash)
	for _, o := range fundingOutputs {
		txn.SiacoinInputs = append(txn.SiacoinInputs, types.SiacoinInput{
			ParentID:         types.SiacoinOutputID(o.ID),
			UnlockConditions: o.UnlockConditions,
		})
		toSign[o.ID] = o.UnlockHash
	}
	// add change output if needed
	if change := outputSum.Sub(amount); !change.IsZero() {
		txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{
			UnlockHash: changeAddr,
			Value:      change,
		})
	}
	return toSign, true
}
