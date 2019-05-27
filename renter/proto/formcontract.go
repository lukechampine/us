package proto

import (
	"math/big"
	"sort"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/ed25519"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renterhost"
)

const (
	// estTxnSize is the estimated size of an encoded file contract
	// transaction set.
	estTxnSize = 2048
)

// FormContract forms a contract with a host. The resulting contract will have
// renterPayout coins in the renter output.
func FormContract(w Wallet, tpool TransactionPool, key ed25519.PrivateKey, host hostdb.ScannedHost, renterPayout types.Currency, startHeight, endHeight types.BlockHeight) (ContractRevision, error) {
	s, err := NewUnlockedSession(host.NetAddress, host.PublicKey, 0)
	if err != nil {
		return ContractRevision{}, err
	}
	s.host = host
	defer s.Close()
	return s.FormContract(w, tpool, key, renterPayout, startHeight, endHeight)
}

// FormContract forms a contract with a host. The resulting contract will have
// renterPayout coins in the renter output.
func (s *Session) FormContract(w Wallet, tpool TransactionPool, key ed25519.PrivateKey, renterPayout types.Currency, startHeight, endHeight types.BlockHeight) (ContractRevision, error) {
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

	// create unlock conditions
	uc := types.UnlockConditions{
		PublicKeys: []types.SiaPublicKey{
			{
				Algorithm: types.SignatureEd25519,
				Key:       []byte(key.PublicKey()),
			},
			s.host.PublicKey.SiaPublicKey(),
		},
		SignaturesRequired: 2,
	}

	// estimate filesize. The filesize will be used to calculate collateral.
	// Note that it's okay to estimate the collateral: the host only cares if
	// we exceed MaxCollateral, and we only care about the tax we pay on it.
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

	// calculate payouts
	hostPayout := s.host.ContractPrice.Add(hostCollateral)
	payout := taxAdjustedPayout(renterPayout.Add(hostPayout))

	// create file contract
	fc := types.FileContract{
		FileSize:       0,
		FileMerkleRoot: crypto.Hash{}, // no proof possible without data
		WindowStart:    endHeight,
		WindowEnd:      endHeight + s.host.WindowSize,
		Payout:         payout,
		UnlockHash:     uc.UnlockHash(),
		RevisionNumber: 0,
		ValidProofOutputs: []types.SiacoinOutput{
			// outputs need to account for tax
			{Value: renterPayout, UnlockHash: refundAddr},
			// collateral is returned to host
			{Value: hostPayout, UnlockHash: s.host.UnlockHash},
		},
		MissedProofOutputs: []types.SiacoinOutput{
			// same as above
			{Value: renterPayout, UnlockHash: refundAddr},
			// same as above
			{Value: hostPayout, UnlockHash: s.host.UnlockHash},
			// once we start doing revisions, we'll move some coins to the host and some to the void
			{Value: types.ZeroCurrency, UnlockHash: types.UnlockHash{}},
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

	// send request
	s.extendDeadline(60 * time.Second)
	req := &renterhost.RPCFormContractRequest{
		Transactions: []types.Transaction{txn},
		RenterKey:    uc.PublicKeys[0],
	}
	if err := s.sess.WriteRequest(renterhost.RPCFormContractID, req); err != nil {
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
	// NOTE: it is not necessary to explicitly check that the host supplied
	// collateral before signing; underpayment will result in an invalid
	// transaction.
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
		s.sess.WriteResponse(nil, errors.New("internal error")) // don't want to reveal too much
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
		CoveredFields:  types.CoveredFields{FileContractRevisions: []uint64{0}},
		PublicKeyIndex: 0,
		Signature:      key.SignHash(crypto.HashObject(initRevision)),
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

func fundSiacoins(txn *types.Transaction, amount types.Currency, changeAddr types.UnlockHash, w Wallet) ([]crypto.Hash, error) {
	outputs, err := w.UnspentOutputs()
	if err != nil {
		return nil, err
	}
	// sort outputs by value, high to low
	sort.Slice(outputs, func(i, j int) bool {
		return outputs[i].Value.Cmp(outputs[j].Value) > 0
	})

	// keep adding outputs until we have enough
	var fundingOutputs []modules.UnspentOutput
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
		return nil, errors.New("insufficient funds to fund contract transaction")
	}

	var toSign []crypto.Hash
	for _, o := range fundingOutputs {
		uc, err := w.UnlockConditions(o.UnlockHash)
		if err != nil {
			return nil, err
		}
		txn.SiacoinInputs = append(txn.SiacoinInputs, types.SiacoinInput{
			ParentID:         types.SiacoinOutputID(o.ID),
			UnlockConditions: uc,
		})
		toSign = append(toSign, crypto.Hash(o.ID))
	}
	// add change output if needed
	if change := outputSum.Sub(amount); !change.IsZero() {
		txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{
			UnlockHash: changeAddr,
			Value:      change,
		})
	}
	return toSign, nil
}

// NOTE: due to a bug in the transaction validation code, calculating payouts
// is way harder than it needs to be. Tax is calculated on the post-tax
// contract payout (instead of the sum of the renter and host payouts). So the
// equation for the payout is:
//
//      payout = renterPayout + hostPayout + payout*tax
//   ∴  payout = (renterPayout + hostPayout) / (1 - tax)
//
// This would work if 'tax' were a simple fraction, but because the tax must
// be evenly distributed among siafund holders, 'tax' is actually a function
// that multiplies by a fraction and then rounds down to the nearest multiple
// of the siafund count. Thus, when inverting the function, we have to make an
// initial guess and then fix the rounding error.
func taxAdjustedPayout(target types.Currency) types.Currency {
	// compute initial guess as target * (1 / 1-tax); since this does not take
	// the siafund rounding into account, the guess will be up to
	// types.SiafundCount greater than the actual payout value.
	guess := target.Big()
	guess.Mul(guess, big.NewInt(1000))
	guess.Div(guess, big.NewInt(961))

	// now, adjust the guess to remove the rounding error. We know that:
	//
	//   (target % types.SiafundCount) == (payout % types.SiafundCount)
	//
	// therefore, we can simply adjust the guess to have this remainder as
	// well. The only wrinkle is that, since we know guess >= payout, if the
	// guess remainder is smaller than the target remainder, we must subtract
	// an extra types.SiafundCount.
	//
	// for example, if target = 87654321 and types.SiafundCount = 10000, then:
	//
	//   initial_guess  = 87654321 * (1 / (1 - tax))
	//                  = 91211572
	//   target % 10000 =     4321
	//   adjusted_guess = 91204321
	sfc := types.SiafundCount.Big()
	tm := new(big.Int).Mod(target.Big(), sfc)
	gm := new(big.Int).Mod(guess, sfc)
	if gm.Cmp(tm) < 0 {
		guess.Sub(guess, sfc)
	}
	guess.Sub(guess, gm)
	guess.Add(guess, tm)

	return types.NewCurrency(guess)
}
