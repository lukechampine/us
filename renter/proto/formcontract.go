package proto

import (
	"crypto/ed25519"
	"math/big"
	"reflect"
	"sort"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/frand"
	"lukechampine.com/us/ed25519hash"
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
func FormContract(w Wallet, tpool TransactionPool, key ed25519.PrivateKey, host hostdb.ScannedHost, renterPayout types.Currency, startHeight, endHeight types.BlockHeight) (ContractRevision, []types.Transaction, error) {
	s, err := NewUnlockedSession(host.NetAddress, host.PublicKey, 0)
	if err != nil {
		return ContractRevision{}, nil, err
	}
	s.host = host
	defer s.Close()
	return s.FormContract(w, tpool, key, renterPayout, startHeight, endHeight)
}

// FormContract forms a contract with a host. The resulting contract will have
// renterPayout coins in the renter output.
func (s *Session) FormContract(w Wallet, tpool TransactionPool, key ed25519.PrivateKey, renterPayout types.Currency, startHeight, endHeight types.BlockHeight) (_ ContractRevision, _ []types.Transaction, err error) {
	defer wrapErr(&err, "FormContract")
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

	// create unlock conditions
	uc := types.UnlockConditions{
		PublicKeys: []types.SiaPublicKey{
			{
				Algorithm: types.SignatureEd25519,
				Key:       []byte(ed25519hash.ExtractPublicKey(key)),
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

	// The host adjusts its contract price dynamically based on the current
	// recommended transaction fee. We don't know how much it will have changed
	// since we last scanned, but adding 5% leeway seems reasonable.
	contractPrice := s.host.ContractPrice.MulFloat(1.05)

	// calculate payouts
	hostPayout := contractPrice.Add(hostCollateral)
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
	// the renter is responsible for paying the contractPrice, the siafund tax,
	// and a transaction fee.
	_, maxFee, err := tpool.FeeEstimate()
	if err != nil {
		return ContractRevision{}, nil, errors.Wrap(err, "could not estimate transaction fee")
	}
	fee := maxFee.Mul64(estTxnSize)
	totalCost := renterPayout.Add(contractPrice).Add(types.Tax(startHeight, fc.Payout)).Add(fee)

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

	// send request
	s.extendDeadline(120 * time.Second)
	req := &renterhost.RPCFormContractRequest{
		Transactions: append(parents, txn),
		RenterKey:    uc.PublicKeys[0],
	}
	if err := s.sess.WriteRequest(renterhost.RPCFormContractID, req); err != nil {
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
		Signature:      ed25519hash.Sign(key, renterhost.HashRevision(initRevision)),
	}

	// Send signatures.
	renterSigs := &renterhost.RPCFormContractSignatures{
		ContractSignatures: addedSignatures,
		RevisionSignature:  renterRevisionSig,
	}
	if err := s.sess.WriteResponse(renterSigs, nil); err != nil {
		return ContractRevision{}, nil, err
	}

	// Read the host signatures.
	var hostSigs renterhost.RPCFormContractSignatures
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

func fundSiacoins(txn *types.Transaction, amount types.Currency, changeAddr types.UnlockHash, w Wallet) ([]crypto.Hash, error) {
	if amount.IsZero() {
		return nil, nil
	}
	// w.UnspentOutputs(true) returns the outputs that exist after Limbo
	// transactions are applied. This is not ideal, because the host is more
	// likely to reject transactions that have unconfirmed parents. On the other
	// hand, w.UnspentOutputs(false) won't return any outputs that were created
	// in Limbo transactions, but it *will* return outputs that have been
	// *spent* in Limbo transactions. So what we really want is the intersection
	// of these sets, keeping only the confirmed outputs that were not spent in
	// Limbo transactions.
	limboOutputs, err := w.UnspentOutputs(true)
	if err != nil {
		return nil, err
	}
	confirmedOutputs, err := w.UnspentOutputs(false)
	if err != nil {
		return nil, err
	}
	var outputs []modules.UnspentOutput
	for _, lo := range limboOutputs {
		for _, co := range confirmedOutputs {
			if co.ID == lo.ID {
				outputs = append(outputs, lo)
				break
			}
		}
	}
	var balance types.Currency
	for _, o := range outputs {
		balance = balance.Add(o.Value)
	}
	if balance.Cmp(amount) < 0 {
		// insufficient funds; proceed with limbo outputs
		outputs = limboOutputs
	}
	// choose outputs randomly
	frand.Shuffle(len(outputs), reflect.Swapper(outputs))

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
		return nil, ErrInsufficientFunds
	}
	// due to the random selection, we may have more outputs than we need; sort
	// by value and discard as many as possible
	sort.Slice(fundingOutputs, func(i, j int) bool {
		return fundingOutputs[i].Value.Cmp(fundingOutputs[j].Value) < 0
	})
	for outputSum.Sub(fundingOutputs[0].Value).Cmp(amount) >= 0 {
		outputSum = outputSum.Sub(fundingOutputs[0].Value)
		fundingOutputs = fundingOutputs[1:]
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
