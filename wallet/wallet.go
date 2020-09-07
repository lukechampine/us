// Package wallet contains types and functions relevant to operating a Sia
// wallet.
package wallet

import (
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"gitlab.com/NebulousLabs/encoding"
	"golang.org/x/crypto/blake2b"
)

// An AddressOwner claims ownership of addresses.
type AddressOwner interface {
	OwnsAddress(addr types.UnlockHash) bool
}

// A ChainStore stores ProcessedConsensusChanges.
type ChainStore interface {
	ApplyConsensusChange(reverted, applied ProcessedConsensusChange, id modules.ConsensusChangeID)
}

// A Store stores information needed by a wallet.
type Store interface {
	AddressOwner
	Addresses() []types.UnlockHash
	AddAddress(info SeedAddressInfo)
	AddressInfo(addr types.UnlockHash) (SeedAddressInfo, bool)
	RemoveAddress(addr types.UnlockHash)
	BlockRewards(n int) []BlockReward
	ConsensusChangeID() modules.ConsensusChangeID
	ChainHeight() types.BlockHeight
	FileContracts(n int) []FileContract
	FileContractHistory(id types.FileContractID) []FileContract
	LimboTransactions() []LimboTransaction
	AddToLimbo(txn types.Transaction)
	RemoveFromLimbo(id types.TransactionID)
	Memo(txid types.TransactionID) []byte
	SetMemo(txid types.TransactionID, memo []byte)
	SeedIndex() uint64
	SetSeedIndex(index uint64)
	Transaction(id types.TransactionID) (Transaction, bool)
	Transactions(n int) []types.TransactionID
	TransactionsByAddress(addr types.UnlockHash, n int) []types.TransactionID
	UnspentOutputs() []UnspentOutput
}

// A ProcessedConsensusChange is a condensation of a modules.ConsensusChange,
// containing only the data relevant to certain addresses, and intended to be
// processed by an atomic unit.
type ProcessedConsensusChange struct {
	Outputs             []UnspentOutput
	Transactions        []Transaction
	AddressTransactions map[types.UnlockHash][]types.TransactionID
	BlockRewards        []BlockReward
	FileContracts       []FileContract
	BlockCount          int
}

// StandardUnlockConditions are the unlock conditions for a standard address:
// one public key, no timelock.
func StandardUnlockConditions(pk types.SiaPublicKey) types.UnlockConditions {
	return types.UnlockConditions{
		PublicKeys:         []types.SiaPublicKey{pk},
		SignaturesRequired: 1,
	}
}

// StandardAddress returns the UnlockHash of a set of StandardUnlockConditions.
func StandardAddress(pk types.SiaPublicKey) types.UnlockHash {
	// To avoid allocating, compute the UnlockHash manually. An UnlockHash is
	// the Merkle root of UnlockConditions, which comprise a timelock, a set
	// of public keys, and the number of signatures required. Since the
	// standard UnlockConditions use a single public key, the Merkle tree is:
	//
	//           ┌─────────┴──────────┐
	//     ┌─────┴─────┐              │
	//  timelock     pubkey     sigsrequired
	//
	// This implies a total of 5 blake2b hashes: 3 leaves and 2 nodes.
	// However, in the standard UnlockConditions, the timelock and
	// sigsrequired are always the same (0 and 1, respectively), so we can
	// precompute these hashes, bringing the total to 3 blake2b hashes.

	// calculate the leaf hash for the pubkey.
	buf := make([]byte, 65)
	buf[0] = 0x00 // Merkle tree leaf prefix
	copy(buf[1:], pk.Algorithm[:])
	binary.LittleEndian.PutUint64(buf[17:], uint64(len(pk.Key)))
	buf = append(buf[:25], pk.Key...) // won't realloc for ed25519 keys
	pubkeyHash := blake2b.Sum256(buf)

	// blake2b(0x00 | uint64(0))
	timelockHash := []byte{
		0x51, 0x87, 0xb7, 0xa8, 0x02, 0x1b, 0xf4, 0xf2,
		0xc0, 0x04, 0xea, 0x3a, 0x54, 0xcf, 0xec, 0xe1,
		0x75, 0x4f, 0x11, 0xc7, 0x62, 0x4d, 0x23, 0x63,
		0xc7, 0xf4, 0xcf, 0x4f, 0xdd, 0xd1, 0x44, 0x1e,
	}
	// blake2b(0x00 | uint64(1))
	sigsrequiredHash := []byte{
		0xb3, 0x60, 0x10, 0xeb, 0x28, 0x5c, 0x15, 0x4a,
		0x8c, 0xd6, 0x30, 0x84, 0xac, 0xbe, 0x7e, 0xac,
		0x0c, 0x4d, 0x62, 0x5a, 0xb4, 0xe1, 0xa7, 0x6e,
		0x62, 0x4a, 0x87, 0x98, 0xcb, 0x63, 0x49, 0x7b,
	}

	buf = buf[:65]
	buf[0] = 0x01 // Merkle tree node prefix
	copy(buf[1:], timelockHash)
	copy(buf[33:], pubkeyHash[:])
	tlpkHash := blake2b.Sum256(buf)
	copy(buf[1:], tlpkHash[:])
	copy(buf[33:], sigsrequiredHash)
	return blake2b.Sum256(buf)
}

// CalculateUnlockHash calculates the UnlockHash of a set of UnlockConditions.
// It calls StandardAddress on "standard" UnlockConditions, falling back to the
// UnlockHash method otherwise. Since the vast majority of UnlockConditions are
// standard, this results in faster average computation.
func CalculateUnlockHash(uc types.UnlockConditions) types.UnlockHash {
	if uc.Timelock == 0 && len(uc.PublicKeys) == 1 && uc.SignaturesRequired == 1 {
		return StandardAddress(uc.PublicKeys[0])
	}
	return uc.UnlockHash()
}

// StandardTransactionSignature is the most common form of TransactionSignature.
// It covers the entire transaction and references the first (typically the
// only) public key.
func StandardTransactionSignature(id crypto.Hash) types.TransactionSignature {
	return types.TransactionSignature{
		ParentID:       id,
		CoveredFields:  types.FullCoveredFields,
		PublicKeyIndex: 0,
	}
}

// An UnspentOutput is a SiacoinOutput along with its ID.
type UnspentOutput struct {
	types.SiacoinOutput
	ID types.SiacoinOutputID
}

// MarshalSia implements encoding.SiaMarshaler.
func (o UnspentOutput) MarshalSia(w io.Writer) error {
	return encoding.NewEncoder(w).EncodeAll(o.SiacoinOutput, o.ID)
}

// UnmarshalSia implements encoding.SiaUnmarshaler.
func (o *UnspentOutput) UnmarshalSia(r io.Reader) error {
	return encoding.NewDecoder(r, encoding.DefaultAllocLimit).DecodeAll(&o.SiacoinOutput, &o.ID)
}

// A ValuedInput is a SiacoinInput along with its value. Seen another way, it is
// an UnspentOutput that knows its UnlockConditions.
type ValuedInput struct {
	types.SiacoinInput
	Value types.Currency
}

// MarshalSia implements encoding.SiaMarshaler.
func (i ValuedInput) MarshalSia(w io.Writer) error {
	return encoding.NewEncoder(w).EncodeAll(i.SiacoinInput, i.Value)
}

// UnmarshalSia implements encoding.SiaUnmarshaler.
func (i *ValuedInput) UnmarshalSia(r io.Reader) error {
	return encoding.NewDecoder(r, encoding.DefaultAllocLimit).DecodeAll(&i.SiacoinInput, &i.Value)
}

// A BlockReward is a timelocked output awarded to the miner of a block.
type BlockReward struct {
	UnspentOutput
	Timelock types.BlockHeight
}

// MarshalSia implements encoding.SiaMarshaler.
func (br BlockReward) MarshalSia(w io.Writer) error {
	return encoding.NewEncoder(w).EncodeAll(br.UnspentOutput, br.Timelock)
}

// UnmarshalSia implements encoding.SiaUnmarshaler.
func (br *BlockReward) UnmarshalSia(r io.Reader) error {
	return encoding.NewDecoder(r, encoding.DefaultAllocLimit).DecodeAll(&br.UnspentOutput, &br.Timelock)
}

// A FileContract is an initial or revised file contract.
type FileContract struct {
	types.FileContract
	UnlockConditions types.UnlockConditions
	ID               types.FileContractID
}

// MarshalSia implements encoding.SiaMarshaler.
func (fc FileContract) MarshalSia(w io.Writer) error {
	return encoding.NewEncoder(w).EncodeAll(fc.FileContract, fc.UnlockConditions, fc.ID)
}

// UnmarshalSia implements encoding.SiaUnmarshaler.
func (fc *FileContract) UnmarshalSia(r io.Reader) error {
	return encoding.NewDecoder(r, encoding.DefaultAllocLimit).DecodeAll(&fc.FileContract, &fc.UnlockConditions, &fc.ID)
}

// A Transaction is an on-chain transaction with additional metadata.
type Transaction struct {
	types.Transaction
	BlockID     types.BlockID
	BlockHeight types.BlockHeight
	Timestamp   time.Time
	FeePerByte  types.Currency
	InputValues []types.Currency
}

// MarshalSia implements encoding.SiaMarshaler.
func (txn Transaction) MarshalSia(w io.Writer) error {
	stamp := txn.Timestamp.Unix()
	return encoding.NewEncoder(w).EncodeAll(txn.Transaction, txn.BlockID, txn.BlockHeight, stamp, txn.FeePerByte, txn.InputValues)
}

// UnmarshalSia implements encoding.SiaUnmarshaler.
func (txn *Transaction) UnmarshalSia(r io.Reader) error {
	var stamp int64
	err := encoding.NewDecoder(r, encoding.DefaultAllocLimit).DecodeAll(&txn.Transaction, &txn.BlockID, &txn.BlockHeight, &stamp, &txn.FeePerByte, &txn.InputValues)
	txn.Timestamp = time.Unix(stamp, 0)
	return err
}

// A LimboTransaction is a transaction that has been broadcast, but has not
// appeared in a block.
type LimboTransaction struct {
	types.Transaction
	LimboSince time.Time
}

// MarshalSia implements encoding.SiaMarshaler.
func (txn LimboTransaction) MarshalSia(w io.Writer) error {
	since := txn.LimboSince.Unix()
	return encoding.NewEncoder(w).EncodeAll(txn.Transaction, since)
}

// UnmarshalSia implements encoding.SiaUnmarshaler.
func (txn *LimboTransaction) UnmarshalSia(r io.Reader) error {
	var since int64
	err := encoding.NewDecoder(r, encoding.DefaultAllocLimit).DecodeAll(&txn.Transaction, &since)
	txn.LimboSince = time.Unix(since, 0)
	return err
}

// A SeedAddressInfo contains the unlock conditions and key index for an
// address derived from a seed.
type SeedAddressInfo struct {
	UnlockConditions types.UnlockConditions `json:"unlockConditions"`
	KeyIndex         uint64                 `json:"keyIndex"`
}

// UnlockHash is a convenience method that returns the address derived from
// info's UnlockConditions.
func (info SeedAddressInfo) UnlockHash() types.UnlockHash {
	return CalculateUnlockHash(info.UnlockConditions)
}

// MarshalJSON implements json.Marshaler.
func (info SeedAddressInfo) MarshalJSON() ([]byte, error) {
	uc := info.UnlockConditions
	pks := make([]string, len(uc.PublicKeys))
	for i := range pks {
		pks[i] = strconv.Quote(uc.PublicKeys[i].String())
	}
	timeLock := ""
	if uc.Timelock != 0 {
		timeLock = fmt.Sprintf(`"timelock":%v,`, uc.Timelock)
	}
	return []byte(fmt.Sprintf(`{"unlockConditions":{%s"publicKeys":[%s],"signaturesRequired":%v},"keyIndex":%v}`,
		timeLock, strings.Join(pks, ","), uc.SignaturesRequired, info.KeyIndex)), nil
}

// CalculateLimboOutputs returns the outputs the owner would control if all
// transactions in limbo were applied.
func CalculateLimboOutputs(owner AddressOwner, limbo []LimboTransaction, outputs []UnspentOutput) []UnspentOutput {
	newOutputs := append([]UnspentOutput(nil), outputs...)
	// first add all newly-created outputs, then delete all spent outputs; this
	// way, the ordering of the limbo transactions (e.g. if one txn creates an
	// output spent by another txn) is irrelevant
	for _, txn := range limbo {
		for i, o := range txn.SiacoinOutputs {
			if owner.OwnsAddress(o.UnlockHash) {
				newOutputs = append(newOutputs, UnspentOutput{
					SiacoinOutput: o,
					ID:            txn.SiacoinOutputID(uint64(i)),
				})
			}
		}
	}
	for _, txn := range limbo {
		for _, o := range txn.SiacoinInputs {
			if owner.OwnsAddress(CalculateUnlockHash(o.UnlockConditions)) {
				for j := range newOutputs {
					if newOutputs[j].ID == o.ParentID {
						newOutputs = append(newOutputs[:j], newOutputs[j+1:]...)
						break
					}
				}
			}
		}
	}
	return newOutputs
}

// FilterConsensusChange extracts the information in cc relevant to the
// specified AddressOwner. Relevance is determined as follows: an output is
// relevant if its UnlockHash is owned by the AddressOwner; a transaction is
// relevant if any of the UnlockHashes or UnlockConditions appearing in it are
// owned by the AddressOwner.
func FilterConsensusChange(cc modules.ConsensusChange, owner AddressOwner, currentHeight types.BlockHeight) (reverted, applied ProcessedConsensusChange, ccid modules.ConsensusChangeID) {
	// ignore "ephemeral" outputs (outputs created and spent in the same
	// ConsensusChange).
	survivingOutputs := make(map[types.SiacoinOutputID]struct{})
	outputValues := make(map[types.SiacoinOutputID]types.Currency)
	for _, diff := range cc.SiacoinOutputDiffs {
		outputValues[diff.ID] = diff.SiacoinOutput.Value
		if _, ok := survivingOutputs[diff.ID]; !ok {
			survivingOutputs[diff.ID] = struct{}{}
		} else {
			delete(survivingOutputs, diff.ID)
		}
	}
	processOutput := func(diff modules.SiacoinOutputDiff, pcc *ProcessedConsensusChange) {
		if _, ok := survivingOutputs[diff.ID]; ok && owner.OwnsAddress(diff.SiacoinOutput.UnlockHash) {
			pcc.Outputs = append(pcc.Outputs, UnspentOutput{
				SiacoinOutput: diff.SiacoinOutput,
				ID:            diff.ID,
			})
		}
		// Perhaps surprisingly, the same output can appear in
		// SiacoinOutputDiffs multiple times. This can happen if e.g. the
		// ConsensusChange contains both a block that spends the output, and a
		// reverted block that destroys the output. We want clients of
		// ChainScanner to only see each output once, so delete from the map
		// here to ensure that we skip any future occurrences of this output.
		delete(survivingOutputs, diff.ID)
	}
	for _, diff := range cc.SiacoinOutputDiffs {
		if diff.Direction == modules.DiffApply {
			processOutput(diff, &applied)
		} else {
			processOutput(diff, &reverted)
		}
	}
	// NOTE: we do not process the DelayedSiacoinOutputDiffs in the same way as
	// above, for two reasons. First, they don't carry enough information (e.g.
	// for a BlockReward, we might want to know the ID of the block); second,
	// they are "reverted" when they expire *or* are invalidated, whereas we
	// want to continue storing block rewards/file contracts indefinitely and
	// only revert them if they are invalidated.

	// more helper functions
	relevantTxn := func(txn types.Transaction) map[types.UnlockHash]struct{} {
		addrs := make(map[types.UnlockHash]struct{})
		processAddr := func(addr types.UnlockHash) {
			if _, ok := addrs[addr]; !ok && owner.OwnsAddress(addr) {
				addrs[addr] = struct{}{}
			}
		}
		for i := range txn.SiacoinInputs {
			processAddr(CalculateUnlockHash(txn.SiacoinInputs[i].UnlockConditions))
		}
		for i := range txn.SiacoinOutputs {
			processAddr(txn.SiacoinOutputs[i].UnlockHash)
		}
		for i := range txn.SiafundInputs {
			processAddr(CalculateUnlockHash(txn.SiafundInputs[i].UnlockConditions))
			processAddr(txn.SiafundInputs[i].ClaimUnlockHash)
		}
		for i := range txn.SiafundOutputs {
			processAddr(txn.SiafundOutputs[i].UnlockHash)
		}
		for i := range txn.FileContracts {
			for _, sco := range txn.FileContracts[i].ValidProofOutputs {
				processAddr(sco.UnlockHash)
			}
			for _, sco := range txn.FileContracts[i].MissedProofOutputs {
				processAddr(sco.UnlockHash)
			}
		}
		for i := range txn.FileContractRevisions {
			for _, sco := range txn.FileContractRevisions[i].NewValidProofOutputs {
				processAddr(sco.UnlockHash)
			}
			for _, sco := range txn.FileContractRevisions[i].NewMissedProofOutputs {
				processAddr(sco.UnlockHash)
			}
		}
		return addrs
	}

	relevantFileContract := func(valid, missed []types.SiacoinOutput) bool {
		relevant := false
		for _, sco := range valid {
			relevant = relevant || owner.OwnsAddress(sco.UnlockHash)
		}
		for _, sco := range missed {
			relevant = relevant || owner.OwnsAddress(sco.UnlockHash)
		}
		return relevant
	}

	processTxns := func(b types.Block, height types.BlockHeight, pcc *ProcessedConsensusChange) {
		bid := b.ID()
		for _, txn := range b.Transactions {
			addrs := relevantTxn(txn)
			if len(addrs) == 0 {
				continue
			}
			if pcc.AddressTransactions == nil {
				pcc.AddressTransactions = make(map[types.UnlockHash][]types.TransactionID)
			}
			txid := txn.ID()
			for addr := range addrs {
				pcc.AddressTransactions[addr] = append(pcc.AddressTransactions[addr], txid)
			}
			var totalFee types.Currency
			for _, fee := range txn.MinerFees {
				totalFee = totalFee.Add(fee)
			}
			inputVals := make([]types.Currency, len(txn.SiacoinInputs))
			for i, sci := range txn.SiacoinInputs {
				inputVals[i] = outputValues[sci.ParentID]
			}
			pcc.Transactions = append(pcc.Transactions, Transaction{
				Transaction: txn,
				BlockID:     bid,
				BlockHeight: height,
				Timestamp:   time.Unix(int64(b.Timestamp), 0),
				FeePerByte:  totalFee.Div64(uint64(txn.MarshalSiaSize())),
				InputValues: inputVals,
			})

			for i, fc := range txn.FileContracts {
				if relevantFileContract(fc.ValidProofOutputs, fc.MissedProofOutputs) {
					pcc.FileContracts = append(pcc.FileContracts, FileContract{
						FileContract:     fc,
						UnlockConditions: types.UnlockConditions{}, // unknown
						ID:               txn.FileContractID(uint64(i)),
					})
				}
			}
			for _, fcr := range txn.FileContractRevisions {
				if relevantFileContract(fcr.NewValidProofOutputs, fcr.NewMissedProofOutputs) {
					// locate payout in cc (FileContractRevision doesn't
					// contain the Payout field)
					//
					// NOTE: we don't want to take the entire FileContract
					// from cc.FileContractDiffs, because it's hard to be
					// sure that we'd be taking the correct revision (since
					// the diff aggregates across all blocks in the cc).
					var payout types.Currency
					for _, diff := range cc.FileContractDiffs {
						if diff.ID == fcr.ParentID {
							payout = diff.FileContract.Payout
							break
						}
					}
					pcc.FileContracts = append(pcc.FileContracts, FileContract{
						FileContract: types.FileContract{
							FileSize:           fcr.NewFileSize,
							FileMerkleRoot:     fcr.NewFileMerkleRoot,
							WindowStart:        fcr.NewWindowStart,
							WindowEnd:          fcr.NewWindowEnd,
							Payout:             payout,
							ValidProofOutputs:  fcr.NewValidProofOutputs,
							MissedProofOutputs: fcr.NewMissedProofOutputs,
							UnlockHash:         fcr.NewUnlockHash,
							RevisionNumber:     fcr.NewRevisionNumber,
						},
						UnlockConditions: fcr.UnlockConditions,
						ID:               fcr.ParentID,
					})
				}
			}
		}
	}
	processMinerPayouts := func(b types.Block, pcc *ProcessedConsensusChange) {
		for i, mp := range b.MinerPayouts {
			if owner.OwnsAddress(mp.UnlockHash) {
				// locate in DSCOs
				id := b.MinerPayoutID(uint64(i))
				for _, diff := range cc.DelayedSiacoinOutputDiffs {
					if diff.ID == id {
						pcc.BlockRewards = append(pcc.BlockRewards, BlockReward{
							UnspentOutput: UnspentOutput{
								SiacoinOutput: diff.SiacoinOutput,
								ID:            id,
							},
							Timelock: diff.MaturityHeight,
						})
						break
					}
				}
			}
		}
	}

	for i, b := range cc.AppliedBlocks {
		processTxns(b, types.BlockHeight(int(currentHeight)+i+1), &applied)
		processMinerPayouts(b, &applied)
		applied.BlockCount++
	}
	for i, b := range cc.RevertedBlocks {
		processTxns(b, types.BlockHeight(int(currentHeight)-i-1), &reverted)
		processMinerPayouts(b, &reverted)
		reverted.BlockCount++
	}

	return reverted, applied, cc.ID
}

// RelevantTransaction returns true if txn is relevant to owner.
func RelevantTransaction(owner AddressOwner, txn types.Transaction) bool {
	for i := range txn.SiacoinInputs {
		if owner.OwnsAddress(CalculateUnlockHash(txn.SiacoinInputs[i].UnlockConditions)) {
			return true
		}
	}
	for i := range txn.SiacoinOutputs {
		if owner.OwnsAddress(txn.SiacoinOutputs[i].UnlockHash) {
			return true
		}
	}
	for i := range txn.SiafundInputs {
		if owner.OwnsAddress(CalculateUnlockHash(txn.SiafundInputs[i].UnlockConditions)) {
			return true
		}
		if owner.OwnsAddress(txn.SiafundInputs[i].ClaimUnlockHash) {
			return true
		}
	}
	for i := range txn.SiafundOutputs {
		if owner.OwnsAddress(txn.SiafundOutputs[i].UnlockHash) {
			return true
		}
	}
	for i := range txn.FileContracts {
		for _, sco := range txn.FileContracts[i].ValidProofOutputs {
			if owner.OwnsAddress(sco.UnlockHash) {
				return true
			}
		}
		for _, sco := range txn.FileContracts[i].MissedProofOutputs {
			if owner.OwnsAddress(sco.UnlockHash) {
				return true
			}
		}
	}
	for i := range txn.FileContractRevisions {
		for _, sco := range txn.FileContractRevisions[i].NewValidProofOutputs {
			if owner.OwnsAddress(sco.UnlockHash) {
				return true
			}
		}
		for _, sco := range txn.FileContractRevisions[i].NewMissedProofOutputs {
			if owner.OwnsAddress(sco.UnlockHash) {
				return true
			}
		}
	}
	return false
}
