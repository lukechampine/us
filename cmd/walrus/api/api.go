package api

import (
	"encoding/hex"
	"encoding/json"
	"time"
	"unsafe"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/wallet"
)

// override transaction marshalling to use camelCase and stringified pubkeys and
// omit empty fields
type encodedSiacoinOutput struct {
	Value      types.Currency   `json:"value"`
	UnlockHash types.UnlockHash `json:"unlockHash"`
}

type encodedUnlockConditions types.UnlockConditions

// MarshalJSON implements json.Marshaler.
func (uc encodedUnlockConditions) MarshalJSON() ([]byte, error) {
	s := struct {
		Timelock           types.BlockHeight `json:"timelock,omitempty"`
		PublicKeys         []string          `json:"publicKeys"`
		SignaturesRequired uint64            `json:"signaturesRequired"`
	}{
		Timelock:           uc.Timelock,
		PublicKeys:         make([]string, len(uc.PublicKeys)),
		SignaturesRequired: uc.SignaturesRequired,
	}
	for i := range s.PublicKeys {
		s.PublicKeys[i] = uc.PublicKeys[i].Algorithm.String() + ":" + hex.EncodeToString(uc.PublicKeys[i].Key)
	}
	return json.Marshal(s)
}

type encodedTransaction struct {
	SiacoinInputs []struct {
		ParentID         types.SiacoinOutputID   `json:"parentID"`
		UnlockConditions encodedUnlockConditions `json:"unlockConditions"`
	} `json:"siacoinInputs,omitempty"`
	SiacoinOutputs []encodedSiacoinOutput `json:"siacoinOutputs,omitempty"`
	FileContracts  []struct {
		FileSize           uint64                 `json:"fileSize"`
		FileMerkleRoot     crypto.Hash            `json:"fileMerkleRoot"`
		WindowStart        types.BlockHeight      `json:"windowStart"`
		WindowEnd          types.BlockHeight      `json:"windowEnd"`
		Payout             types.Currency         `json:"payout"`
		ValidProofOutputs  []encodedSiacoinOutput `json:"validProofOutputs"`
		MissedProofOutputs []encodedSiacoinOutput `json:"missedProofOutputs"`
		UnlockHash         types.UnlockHash       `json:"unlockHash"`
		RevisionNumber     uint64                 `json:"revisionNumber"`
	} `json:"fileContracts,omitempty"`
	FileContractRevisions []struct {
		ParentID              types.FileContractID    `json:"parentID"`
		UnlockConditions      encodedUnlockConditions `json:"unlockConditions"`
		NewRevisionNumber     uint64                  `json:"newRevisionNumber"`
		NewFileSize           uint64                  `json:"newFileSize"`
		NewFileMerkleRoot     crypto.Hash             `json:"newFileMerkleRoot"`
		NewWindowStart        types.BlockHeight       `json:"newWindowStart"`
		NewWindowEnd          types.BlockHeight       `json:"newWindowEnd"`
		NewValidProofOutputs  []encodedSiacoinOutput  `json:"newValidProofOutputs"`
		NewMissedProofOutputs []encodedSiacoinOutput  `json:"newMissedProofOutputs"`
		NewUnlockHash         types.UnlockHash        `json:"newUnlockHash"`
	} `json:"fileContractRevisions,omitempty"`
	StorageProofs []types.StorageProof `json:"storageProofs,omitempty"`
	SiafundInputs []struct {
		ParentID         types.SiafundOutputID   `json:"parentID"`
		UnlockConditions encodedUnlockConditions `json:"unlockConditions"`
		ClaimUnlockHash  types.UnlockHash        `json:"claimUnlockHash"`
	} `json:"siafundInputs,omitempty"`
	SiafundOutputs []struct {
		Value      types.Currency   `json:"value"`
		UnlockHash types.UnlockHash `json:"unlockHash"`
		ClaimStart types.Currency   `json:"-"` // internal, must always be 0
	} `json:"siafundOutputs,omitempty"`
	MinerFees             []types.Currency `json:"minerFees,omitempty"`
	ArbitraryData         [][]byte         `json:"arbitraryData,omitempty"`
	TransactionSignatures []struct {
		ParentID       crypto.Hash       `json:"parentID"`
		PublicKeyIndex uint64            `json:"publicKeyIndex"`
		Timelock       types.BlockHeight `json:"timelock,omitempty"`
		CoveredFields  struct {
			WholeTransaction      bool     `json:"wholeTransaction,omitempty"`
			SiacoinInputs         []uint64 `json:"siacoinInputs,omitempty"`
			SiacoinOutputs        []uint64 `json:"siacoinOutputs,omitempty"`
			FileContracts         []uint64 `json:"fileContracts,omitempty"`
			FileContractRevisions []uint64 `json:"fileContractRevisions,omitempty"`
			StorageProofs         []uint64 `json:"storageProofs,omitempty"`
			SiafundInputs         []uint64 `json:"siafundInputs,omitempty"`
			SiafundOutputs        []uint64 `json:"siafundOutputs,omitempty"`
			MinerFees             []uint64 `json:"minerFees,omitempty"`
			ArbitraryData         []uint64 `json:"arbitraryData,omitempty"`
			TransactionSignatures []uint64 `json:"transactionSignatures,omitempty"`
		} `json:"coveredFields"`
		Signature []byte `json:"signature"`
	} `json:"transactionSignatures,omitempty"`
}

// RequestBroadcast is the request type for the /broadcast endpoint.
type RequestBroadcast []types.Transaction

// RequestSign is the request type for the /sign endpoint.
type RequestSign struct {
	Transaction types.Transaction `json:"transaction"`
	ToSign      []int             `json:"toSign"`
}

// RequestAddresses is the request type for the /addresses endpoint.
type RequestAddresses wallet.SeedAddressInfo

// ResponseAddresses is the response type for the /addresses endpoint.
type ResponseAddresses []types.UnlockHash

// ResponseAddressesAddr is the response type for the /addresses/:addr endpoint.
type ResponseAddressesAddr wallet.SeedAddressInfo

// MarshalJSON implements json.Marshaler.
func (r ResponseAddressesAddr) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		UnlockConditions encodedUnlockConditions `json:"unlockConditions"`
		KeyIndex         uint64                  `json:"keyIndex"`
	}{encodedUnlockConditions(r.UnlockConditions), r.KeyIndex})
}

// ResponseBalance is the response type for the /balance endpoint.
type ResponseBalance types.Currency

// ResponseConsensus is the response type for the /consensus endpoint.
type ResponseConsensus struct {
	Height types.BlockHeight `json:"height"`
	CCID   crypto.Hash       `json:"ccid"`
}

// ResponseLimboUTXOs is the response type for the /limbo endpoint.
type ResponseLimboUTXOs []wallet.LimboOutput

// MarshalJSON implements json.Marshaler.
func (r ResponseLimboUTXOs) MarshalJSON() ([]byte, error) {
	enc := make([]struct {
		ID         types.SiacoinOutputID `json:"ID"`
		Value      types.Currency        `json:"value"`
		UnlockHash types.UnlockHash      `json:"unlockHash"`
		LimboSince time.Time             `json:"limboSince"`
	}, len(r))
	for i := range enc {
		enc[i].ID = r[i].ID
		enc[i].Value = r[i].Value
		enc[i].UnlockHash = r[i].UnlockHash
		enc[i].LimboSince = r[i].LimboSince
	}
	return json.Marshal(enc)
}

// ResponseNextAddress is the response type for the /nextaddress endpoint.
type ResponseNextAddress types.UnlockHash

// ResponseSeedIndex is the response type for the /seedindex endpoint.
type ResponseSeedIndex uint64

// ResponseSign is the response type for the /sign endpoint.
type ResponseSign types.Transaction

// MarshalJSON implements json.Marshaler.
func (r ResponseSign) MarshalJSON() ([]byte, error) {
	return json.Marshal(*(*encodedTransaction)(unsafe.Pointer(&r)))
}

// ResponseTransactions is the response type for the /transactions endpoint.
type ResponseTransactions []types.TransactionID

// ResponseTransactionsID is the response type for the /transactions/:id
// endpoint.
type ResponseTransactionsID struct {
	Transaction types.Transaction `json:"transaction"`
	Inflow      types.Currency    `json:"inflow"`
	Outflow     types.Currency    `json:"outflow"`
	FeePerByte  types.Currency    `json:"feePerByte"`
}

// MarshalJSON implements json.Marshaler.
func (r ResponseTransactionsID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Transaction encodedTransaction `json:"transaction"`
		Inflow      types.Currency     `json:"inflow"`
		Outflow     types.Currency     `json:"outflow"`
		FeePerByte  types.Currency     `json:"feePerByte"`
	}{*(*encodedTransaction)(unsafe.Pointer(&r.Transaction)), r.Inflow, r.Outflow, r.FeePerByte})
}

// A UTXO is an unspent transaction output, ready to be used as a SiacoinInput.
type UTXO struct {
	ID               types.SiacoinOutputID  `json:"ID"`
	Value            types.Currency         `json:"value"`
	UnlockConditions types.UnlockConditions `json:"unlockConditions"`
	UnlockHash       types.UnlockHash       `json:"unlockHash"`
}

// ResponseUTXOs is the response type for the /utxos endpoint.
type ResponseUTXOs []UTXO

// A SeedUTXO is a UTXO owned by a seed-derived address.
type SeedUTXO struct {
	UTXO
	KeyIndex uint64 `json:"keyIndex"`
}

// ResponseSeedUTXOs is the response type for the /utxos endpoint.
type ResponseSeedUTXOs []SeedUTXO
