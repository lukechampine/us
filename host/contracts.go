package host

import (
	"crypto/ed25519"
	"fmt"
	"math"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/ed25519hash"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renterhost"
)

func calculateRevision(currentRevision types.FileContractRevision, newRevisionNumber uint64, newValid, newMissed []types.Currency) (types.FileContractRevision, error) {
	if len(newValid) != len(currentRevision.NewValidProofOutputs) || len(newMissed) != len(currentRevision.NewMissedProofOutputs) {
		return types.FileContractRevision{}, errors.New("wrong number of valid/missed proof values")
	}
	newRevision := currentRevision
	newRevision.NewRevisionNumber = newRevisionNumber
	newRevision.NewValidProofOutputs = make([]types.SiacoinOutput, len(currentRevision.NewValidProofOutputs))
	for i := range newRevision.NewValidProofOutputs {
		newRevision.NewValidProofOutputs[i] = types.SiacoinOutput{
			Value:      newValid[i],
			UnlockHash: currentRevision.NewValidProofOutputs[i].UnlockHash,
		}
	}
	newRevision.NewMissedProofOutputs = make([]types.SiacoinOutput, len(currentRevision.NewMissedProofOutputs))
	for i := range newRevision.NewMissedProofOutputs {
		newRevision.NewMissedProofOutputs[i] = types.SiacoinOutput{
			Value:      newMissed[i],
			UnlockHash: currentRevision.NewMissedProofOutputs[i].UnlockHash,
		}
	}
	return newRevision, nil
}

// ContractManager ...
type ContractManager struct {
	secretKey ed25519.PrivateKey
	store     ContractStore
}

func (cm *ContractManager) publicKey() types.SiaPublicKey {
	return types.SiaPublicKey{
		Algorithm: types.SignatureEd25519,
		Key:       ed25519hash.ExtractPublicKey(cm.secretKey),
	}
}

// Acquire ...
func (cm *ContractManager) Acquire(id types.FileContractID, timeout time.Duration) (Contract, error) {
	// TODO: actually lock
	return cm.store.Contract(id)
}

// Release ...
func (cm *ContractManager) Release(id types.FileContractID) error {
	return nil
}

type contractBuilder struct {
	// TODO: order these temporally, with comments about when each field becomes valid

	contract      types.FileContract
	transaction   types.Transaction
	parents       []types.Transaction
	renterKey     types.SiaPublicKey
	settings      hostdb.HostSettings
	currentHeight types.BlockHeight
	minFee        types.Currency

	hostAdditions renterhost.RPCFormContractAdditions
	renterSigs    renterhost.RPCFormContractSignatures
	hostSigs      renterhost.RPCFormContractSignatures

	// only used for renewals
	finalRevision   types.FileContractRevision
	renterRenewSigs renterhost.RPCRenewAndClearContractSignatures
	hostRenewSigs   renterhost.RPCRenewAndClearContractSignatures
}

// ConsiderFormRequest ...
func (cm *ContractManager) ConsiderFormRequest(cb *contractBuilder) error {
	fc := cb.contract
	switch {
	case fc.FileSize != 0:
		return errors.New("initial filesize should be 0")
	case fc.RevisionNumber != 0:
		// TODO: probably ok to be more lax here, but how lax? math.MaxUint64 - 1?
		return errors.New("initial revision number should be 0")
	case fc.FileMerkleRoot != (crypto.Hash{}):
		return errors.New("initial Merkle root should be empty")
	case fc.WindowStart < cb.currentHeight+cb.settings.WindowSize:
		return errors.New("contract ends too soon to safely submit the contract transaction")
	case fc.WindowStart > cb.currentHeight+cb.settings.MaxDuration:
		return errors.New("contract duration is too long")
	case fc.WindowEnd < fc.WindowStart+cb.settings.WindowSize:
		return errors.New("proof window is too small")
	case len(fc.ValidProofOutputs) != 2 || len(fc.MissedProofOutputs) != 3:
		return errors.New("wrong number of valid/missed outputs")
	case fc.ValidHostOutput().UnlockHash != cb.settings.UnlockHash || fc.MissedHostOutput().UnlockHash != cb.settings.UnlockHash:
		return errors.New("wrong address for host payout")
	case !fc.ValidRenterPayout().Equals(fc.MissedRenterOutput().Value) || !fc.ValidHostPayout().Equals(fc.MissedHostOutput().Value):
		return errors.New("initial valid/missed output values should be the same")
	case fc.ValidHostPayout().Cmp(cb.settings.ContractPrice) < 0:
		return errors.New("insufficient initial host payout")
	case fc.ValidHostPayout().Sub(cb.settings.ContractPrice).Cmp(cb.settings.MaxCollateral) > 0:
		return errors.New("excessive initial collateral")
	case fc.MissedProofOutputs[2].UnlockHash != (types.UnlockHash{}):
		return errors.New("wrong address for void payout")
	case !fc.MissedProofOutputs[2].Value.IsZero():
		return errors.New("wrong value for void payout")
	case modules.CalculateFee(append(cb.parents, cb.transaction)).Cmp(cb.minFee) < 0:
		return errors.New("insufficient transaction fees")
	}

	expectedUnlockHash := types.UnlockConditions{
		PublicKeys:         []types.SiaPublicKey{cb.renterKey, cm.publicKey()},
		SignaturesRequired: 2,
	}.UnlockHash()
	if fc.UnlockHash != expectedUnlockHash {
		return errors.New("wrong unlock hash")
	}

	// both valid and missed outputs should sum to fc.Payout-fee
	var validSum, missedSum types.Currency
	for _, o := range fc.ValidProofOutputs {
		validSum = validSum.Add(o.Value)
	}
	for _, o := range fc.MissedProofOutputs {
		missedSum = missedSum.Add(o.Value)
	}
	if !validSum.Equals(missedSum) || !validSum.Equals(types.PostTax(fc.WindowEnd, fc.Payout)) {
		return errors.New("valid/missed output values do not sum to contract payout")
	}

	return nil
}

// AcceptContract ...
func (cm *ContractManager) AcceptContract(cb *contractBuilder) error {
	// TODO: validate contract txn

	// create initial (no-op revision)
	initRevision := types.FileContractRevision{
		ParentID: cb.transaction.FileContractID(0),
		UnlockConditions: types.UnlockConditions{
			PublicKeys:         []types.SiaPublicKey{cb.renterKey, cm.publicKey()},
			SignaturesRequired: 2,
		},
		NewRevisionNumber: 1,

		NewFileSize:           cb.contract.FileSize,
		NewFileMerkleRoot:     cb.contract.FileMerkleRoot,
		NewWindowStart:        cb.contract.WindowStart,
		NewWindowEnd:          cb.contract.WindowEnd,
		NewValidProofOutputs:  cb.contract.ValidProofOutputs,
		NewMissedProofOutputs: cb.contract.MissedProofOutputs,
		NewUnlockHash:         cb.contract.UnlockHash,
	}
	cb.hostSigs.RevisionSignature = types.TransactionSignature{
		ParentID:       crypto.Hash(initRevision.ParentID),
		CoveredFields:  types.CoveredFields{FileContractRevisions: []uint64{0}},
		PublicKeyIndex: 1,
		Signature:      ed25519hash.Sign(cm.secretKey, renterhost.HashRevision(initRevision)),
	}
	err := cm.store.AddContract(Contract{
		Revision: initRevision,
		Signatures: [2]types.TransactionSignature{
			cb.renterSigs.RevisionSignature,
			cb.hostSigs.RevisionSignature,
		},
		FormationSet:       append(cb.parents, cb.transaction),
		FinalizationHeight: cb.contract.WindowStart - cb.settings.WindowSize,
		ProofHeight:        cb.contract.WindowStart - 1,
	})
	if err != nil {
		return err
	}

	return nil
}

// ConsiderRenewRequest ...
func (cm *ContractManager) ConsiderRenewRequest(cb *contractBuilder, old types.FileContractRevision) error {
	fc := cb.contract
	switch {
	case fc.FileSize != old.NewFileSize:
		return errors.New("initial filesize should match previous contract")
	case fc.RevisionNumber != 0:
		return errors.New("initial revision number should be 0")
	case fc.FileMerkleRoot != old.NewFileMerkleRoot:
		return errors.New("initial Merkle root should match previous contract")
	case fc.WindowStart < cb.currentHeight+cb.settings.WindowSize:
		return errors.New("contract ends too soon to safely submit the contract transaction")
	case fc.WindowStart > cb.currentHeight+cb.settings.MaxDuration:
		return errors.New("contract duration is too long")
	case fc.WindowEnd < fc.WindowStart+cb.settings.WindowSize:
		return errors.New("proof window is too small")
	case len(fc.ValidProofOutputs) != 2 || len(fc.MissedProofOutputs) != 3:
		return errors.New("wrong number of valid/missed outputs")
	case fc.ValidHostOutput().UnlockHash != cb.settings.UnlockHash || fc.MissedHostOutput().UnlockHash != cb.settings.UnlockHash:
		return errors.New("wrong address for host payout")
	case fc.MissedProofOutputs[2].UnlockHash != (types.UnlockHash{}):
		return errors.New("wrong address for void payout")
	case modules.CalculateFee(append(cb.parents, cb.transaction)).Cmp(cb.minFee) < 0:
		return errors.New("insufficient transaction fees")
	}
	expectedUnlockHash := types.UnlockConditions{
		PublicKeys:         []types.SiaPublicKey{cb.renterKey, cm.publicKey()},
		SignaturesRequired: 2,
	}.UnlockHash()
	if fc.UnlockHash != expectedUnlockHash {
		return errors.New("wrong unlock hash")
	}
	// both valid and missed outputs should sum to fc.Payout-fee
	var validSum, missedSum types.Currency
	for _, o := range fc.ValidProofOutputs {
		validSum = validSum.Add(o.Value)
	}
	for _, o := range fc.MissedProofOutputs {
		missedSum = missedSum.Add(o.Value)
	}
	if !validSum.Equals(missedSum) || !validSum.Equals(types.PostTax(fc.WindowEnd, fc.Payout)) {
		return errors.New("valid/missed output values do not sum to contract payout")
	}

	// validate payment and collateral
	var basePrice, baseCollateral types.Currency
	if fc.WindowEnd > old.NewWindowEnd {
		timeExtension := uint64(fc.WindowEnd - old.NewWindowEnd)
		basePrice = cb.settings.StoragePrice.Mul64(fc.FileSize).Mul64(timeExtension)
		baseCollateral = cb.settings.Collateral.Mul64(fc.FileSize).Mul64(timeExtension)
	}
	if initialPayment := cb.settings.ContractPrice.Add(basePrice); fc.ValidHostPayout().Cmp(initialPayment) < 0 {
		return errors.New("insufficient initial valid host payout")
	} else if newCollateral := fc.ValidHostPayout().Sub(initialPayment); newCollateral.Cmp(cb.settings.MaxCollateral) > 0 {
		return errors.New("excessive collateral")
	} else if expectedVoidOutput := basePrice.Add(baseCollateral); fc.MissedProofOutputs[2].Value.Cmp(expectedVoidOutput) > 0 {
		return errors.New("excessive missed void payout")
	} else if fc.ValidHostPayout().Cmp(expectedVoidOutput) < 0 {
		return errors.New("insufficient initial valid host payout")
	} else if expectedHostMissedOutput := fc.ValidHostPayout().Sub(expectedVoidOutput); fc.MissedHostOutput().Value.Cmp(expectedHostMissedOutput) < 0 {
		return errors.New("insufficient missed host payout")
	}

	return nil
}

// AcceptRenewal ...
func (cm *ContractManager) AcceptRenewal(cb *contractBuilder) error {
	// TODO: validate contract txn

	// create initial (no-op revision)
	initRevision := types.FileContractRevision{
		ParentID: cb.transaction.FileContractID(0),
		UnlockConditions: types.UnlockConditions{
			PublicKeys:         []types.SiaPublicKey{cb.renterKey, cm.publicKey()},
			SignaturesRequired: 2,
		},
		NewRevisionNumber: 1,

		NewFileSize:           cb.contract.FileSize,
		NewFileMerkleRoot:     cb.contract.FileMerkleRoot,
		NewWindowStart:        cb.contract.WindowStart,
		NewWindowEnd:          cb.contract.WindowEnd,
		NewValidProofOutputs:  cb.contract.ValidProofOutputs,
		NewMissedProofOutputs: cb.contract.MissedProofOutputs,
		NewUnlockHash:         cb.contract.UnlockHash,
	}
	cb.hostRenewSigs.RevisionSignature = types.TransactionSignature{
		ParentID:       crypto.Hash(initRevision.ParentID),
		CoveredFields:  types.CoveredFields{FileContractRevisions: []uint64{0}},
		PublicKeyIndex: 1,
		Signature:      ed25519hash.Sign(cm.secretKey, renterhost.HashRevision(initRevision)),
	}
	cb.hostRenewSigs.FinalRevisionSignature = ed25519hash.Sign(cm.secretKey, renterhost.HashRevision(cb.finalRevision))

	err := cm.store.AddContract(Contract{
		Revision: initRevision,
		Signatures: [2]types.TransactionSignature{
			cb.renterRenewSigs.RevisionSignature,
			cb.hostRenewSigs.RevisionSignature,
		},
		FormationSet:       append(cb.parents, cb.transaction),
		FinalizationHeight: cb.contract.WindowStart - cb.settings.WindowSize,
		ProofHeight:        cb.contract.WindowStart - 1,
	})
	if err != nil {
		return err
	}
	oldContract, err := cm.store.Contract(cb.finalRevision.ID())
	if err != nil {
		return err
	}
	oldContract.Revision = cb.finalRevision
	oldContract.Signatures[0].Signature = cb.renterRenewSigs.FinalRevisionSignature
	oldContract.Signatures[1].Signature = cb.hostRenewSigs.FinalRevisionSignature
	if err := cm.store.AddContract(oldContract); err != nil {
		return err
	}
	return nil
}

type revisionCharges struct {
	Up, Down       uint64
	Storage        uint64
	SectorAccesses uint64
}

// ConsiderRevision ...
func (cm *ContractManager) ConsiderRevision(old, rev types.FileContractRevision, charges revisionCharges, settings hostdb.HostSettings, currentHeight types.BlockHeight) error {
	switch {
	case rev.ParentID != old.ParentID:
		return errors.New("parent ID must not change")
	case rev.UnlockConditions.UnlockHash() != old.NewUnlockHash:
		return errors.New("unlock conditions must not change")
	case rev.NewUnlockHash != old.NewUnlockHash:
		return errors.New("unlock hash must not change")
	case rev.NewRevisionNumber <= old.NewRevisionNumber:
		return errors.New("revision number must increase")
	case rev.NewWindowStart != old.NewWindowStart:
		return errors.New("window start must not change")
	case rev.NewWindowEnd != old.NewWindowEnd:
		return errors.New("window end must not change")
	case len(rev.NewValidProofOutputs) != len(old.NewValidProofOutputs):
		return errors.New("number of valid outputs must not change")
	case len(rev.NewMissedProofOutputs) != len(old.NewMissedProofOutputs):
		return errors.New("number of valid outputs must not change")
	case rev.ValidRenterOutput().UnlockHash != old.ValidRenterOutput().UnlockHash:
		return errors.New("address of valid renter output must not change")
	case rev.ValidHostOutput().UnlockHash != old.ValidHostOutput().UnlockHash:
		return errors.New("address of valid host output must not change")
	case rev.MissedRenterOutput().UnlockHash != old.MissedRenterOutput().UnlockHash:
		return errors.New("address of missed renter output must not change")
	case rev.MissedHostOutput().UnlockHash != old.MissedHostOutput().UnlockHash:
		return errors.New("address of missed host output must not change")
	case rev.NewMissedProofOutputs[2].UnlockHash != old.NewMissedProofOutputs[2].UnlockHash:
		return errors.New("address of void output must not change")
	}
	// payout sums must match
	var validPayout, missedPayout, oldPayout types.Currency
	for _, output := range rev.NewValidProofOutputs {
		validPayout = validPayout.Add(output.Value)
	}
	for _, output := range rev.NewMissedProofOutputs {
		missedPayout = missedPayout.Add(output.Value)
	}
	for _, output := range old.NewValidProofOutputs {
		oldPayout = oldPayout.Add(output.Value)
	}
	if !validPayout.Equals(oldPayout) || !missedPayout.Equals(oldPayout) {
		return errors.New("sum of outputs must not change")
	}

	if charges.Up > 0 && charges.Up < renterhost.MinMessageSize {
		charges.Up = renterhost.MinMessageSize
	}
	if charges.Down > 0 && charges.Down < renterhost.MinMessageSize {
		charges.Down = renterhost.MinMessageSize
	}
	duration := uint64(rev.NewWindowEnd - currentHeight)

	totalPayment := settings.BaseRPCPrice.
		Add(settings.UploadBandwidthPrice.Mul64(charges.Up)).
		Add(settings.DownloadBandwidthPrice.Mul64(charges.Down)).
		Add(settings.SectorAccessPrice.Mul64(charges.SectorAccesses)).
		Add(settings.StoragePrice.Mul64(charges.Storage).Mul64(duration))
	minValid := old.ValidHostPayout().Add(totalPayment)

	totalCollateral := settings.Collateral.Mul64(charges.Storage).Mul64(duration)
	if totalCollateral.Cmp(old.MissedHostPayout()) > 0 {
		totalCollateral = old.MissedHostPayout()
	}
	minMissed := old.MissedHostPayout().Sub(totalCollateral)

	// we already confirmed that the sum of the payouts is the same, so we only
	// need to check that our valid output isn't less than expected
	if rev.ValidHostPayout().Cmp(minValid) < 0 {
		// TODO: include as much information as possible in this error, esp. block height
		return fmt.Errorf("insufficient payment to host: expected %v, got %v", minValid, rev.ValidHostPayout())
	}
	// Likewise, we only need to check that our collateral isn't more than
	// expected, and that the renter's missed output didn't increase. (The
	// renter is free to move their coins to the void output if they so desire.)
	if rev.MissedHostPayout().Cmp(minMissed) < 0 {
		// TODO: include as much information as possible in this error
		return errors.New("excessive collateral")
	} else if rev.MissedRenterOutput().Value.Cmp(old.MissedRenterOutput().Value) > 0 {
		return errors.New("renter's missed output should never increase")
	}

	return nil
}

// ConsiderFinalRevision ...
func (cm *ContractManager) ConsiderFinalRevision(cb *contractBuilder, old types.FileContractRevision, newValid, newMissed []types.Currency) error {
	if len(newValid) != len(old.NewValidProofOutputs) {
		return errors.New("wrong number of valid proof values")
	} else if len(newValid) != len(newMissed) {
		return errors.New("wrong number of missed proof values")
	}
	for i := range newValid {
		if !newValid[i].Equals(newMissed[i]) {
			return errors.New("valid and missed values must be equal")
		}
	}
	var oldPayout, newPayout types.Currency
	for _, output := range old.NewValidProofOutputs {
		oldPayout = oldPayout.Add(output.Value)
	}
	for _, value := range newValid {
		newPayout = newPayout.Add(value)
	}
	if !newPayout.Equals(oldPayout) {
		return errors.New("sum of outputs must not change")
	}
	finalHostPayout := newValid[1]
	if finalHostPayout.Cmp(old.ValidHostPayout()) < 0 {
		return errors.New("revision decreases host payout")
	}
	payment := finalHostPayout.Sub(old.ValidHostPayout())
	expectedPayment := cb.settings.BaseRPCPrice
	if expectedPayment.Cmp(old.ValidRenterPayout()) > 0 {
		// if the contract had less than BaseRPCPrice left in it, fine; not
		// worth rejecting a renewal over such a small amount
		expectedPayment = old.ValidRenterPayout()
	}
	if payment.Cmp(expectedPayment) < 0 {
		return fmt.Errorf("insufficient payment to host: expected %v, got %v", expectedPayment, payment)
	}

	// compute final revision
	cb.finalRevision = old
	cb.finalRevision.NewRevisionNumber = math.MaxUint64
	cb.finalRevision.NewFileMerkleRoot = crypto.Hash{}
	cb.finalRevision.NewFileSize = 0
	cb.finalRevision.NewValidProofOutputs = append([]types.SiacoinOutput(nil), old.NewValidProofOutputs...)
	for i, value := range newValid {
		cb.finalRevision.NewValidProofOutputs[i].Value = value
	}
	cb.finalRevision.NewMissedProofOutputs = cb.finalRevision.NewValidProofOutputs
	return nil
}

// AcceptRevision ...
func (cm *ContractManager) AcceptRevision(rev types.FileContractRevision, renterSig []byte) ([]byte, error) {
	contract, err := cm.store.Contract(rev.ID())
	if err != nil {
		return nil, err
	}
	hostSig := ed25519hash.Sign(cm.secretKey, renterhost.HashRevision(rev))
	contract.Revision = rev
	contract.Signatures[0].Signature = renterSig
	contract.Signatures[1].Signature = hostSig
	if err := cm.store.AddContract(contract); err != nil {
		return nil, err
	}
	return hostSig, nil
}

// NewContractManager returns an initialized contract manager.
func NewContractManager(key ed25519.PrivateKey, store ContractStore) *ContractManager {
	return &ContractManager{
		secretKey: key,
		store:     store,
	}
}
