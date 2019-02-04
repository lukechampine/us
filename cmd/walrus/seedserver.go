package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"unsafe"

	"github.com/julienschmidt/httprouter"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/wallet"
)

func writeJSON(w io.Writer, v interface{}) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")
	enc.Encode(v)
}

type seedServer struct {
	w  *wallet.SeedWallet
	tp wallet.TransactionPool
}

// ResponseAddresses is the response type for the /addresses endpoint.
type ResponseAddresses []types.UnlockHash

func (s *seedServer) addressesHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	resp := s.w.Addresses()
	if resp == nil {
		resp = ResponseAddresses{}
	}
	writeJSON(w, resp)
}

// ResponseAddressesAddr is the response type for the /addresses/:addr endpoint.
type ResponseAddressesAddr SeedAddressInfo

func (s *seedServer) addressesaddrHandlerGET(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var addr types.UnlockHash
	if err := addr.LoadString(ps.ByName("addr")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	info, ok := s.w.AddressInfo(addr)
	if !ok {
		http.Error(w, "No such entry", http.StatusNoContent)
		return
	}
	writeJSON(w, info)
}

// ResponseBalance is the response type for the /balance endpoint.
type ResponseBalance types.Currency

func (s *seedServer) balanceHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	writeJSON(w, s.w.Balance())
}

// RequestBroadcast is the request type for the /broadcast endpoint.
type RequestBroadcast []types.Transaction

func (s *seedServer) broadcastHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	var txnSet RequestBroadcast
	if err := json.NewDecoder(req.Body).Decode(&txnSet); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if len(txnSet) == 0 {
		http.Error(w, "Transaction set is empty", http.StatusBadRequest)
		return
	}

	// add any unconfirmed parents of the first transaction in the set
	parents := wallet.UnconfirmedParents(txnSet[0], s.tp)

	// submit the transaction set (ignoring duplicate error -- if the set is
	// already in the tpool, great)
	err := s.tp.AcceptTransactionSet(append(parents, txnSet...))
	if err != nil && err != modules.ErrDuplicateTransactionSet {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// mark all wallet-owned inputs as spent
	// TODO: wouldn't need this if wallet was subscribed to tpool
	for _, txn := range txnSet {
		for _, sci := range txn.SiacoinInputs {
			if s.w.OwnsAddress(sci.UnlockConditions.UnlockHash()) {
				s.w.MarkSpent(sci.ParentID, true)
			}
		}
	}
}

// ResponseConsensus is the response type for the /consensus endpoint.
type ResponseConsensus struct {
	Height types.BlockHeight         `json:"height"`
	CCID   modules.ConsensusChangeID `json:"ccid"`
}

func (s *seedServer) consensusHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	writeJSON(w, ResponseConsensus{
		Height: s.w.ChainHeight(),
		CCID:   s.w.ConsensusChangeID(),
	})
}

func (s *seedServer) limboHandlerPUT(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var id crypto.Hash
	if err := id.LoadString(ps.ByName("id")); err != nil {
		http.Error(w, "Invalid ID: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.w.MarkSpent(types.SiacoinOutputID(id), true)
}

func (s *seedServer) limboHandlerDELETE(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var id crypto.Hash
	if err := id.LoadString(ps.ByName("id")); err != nil {
		http.Error(w, "Invalid ID: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.w.MarkSpent(types.SiacoinOutputID(id), false)
}

// ResponseNextAddress is the response type for the /nextaddress endpoint.
type ResponseNextAddress types.UnlockHash

func (s *seedServer) nextaddressHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	addr := s.w.NextAddress()
	writeJSON(w, addr)
}

// ResponseSeedIndex is the response type for the /seedindex endpoint.
type ResponseSeedIndex uint64

func (s *seedServer) seedindexHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	writeJSON(w, s.w.SeedIndex())
}

// RequestSign is the request type for the /sign endpoint.
type RequestSign struct {
	Transaction types.Transaction `json:"transaction"`
	ToSign      []int             `json:"toSign"`
}

// ResponseSign is the response type for the /sign endpoint.
type ResponseSign encodedTransaction

func (s *seedServer) signHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	var rs RequestSign
	if err := json.NewDecoder(req.Body).Decode(&rs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if err := s.w.SignTransaction(&rs.Transaction, rs.ToSign); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, (*ResponseSign)(unsafe.Pointer(&rs.Transaction)))
}

// ResponseTransactions is the response type for the /transactions endpoint.
type ResponseTransactions []types.TransactionID

func (s *seedServer) transactionsHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	max := -1 // all txns
	if req.FormValue("max") != "" {
		var err error
		max, err = strconv.Atoi(req.FormValue("max"))
		if err != nil {
			http.Error(w, "Could not decode request body: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	var resp ResponseTransactions
	if req.FormValue("addr") != "" {
		var addr types.UnlockHash
		if err := addr.LoadString(req.FormValue("addr")); err != nil {
			http.Error(w, "Invalid address: "+err.Error(), http.StatusBadRequest)
			return
		}
		resp = s.w.TransactionsByAddress(addr, max)
	} else {
		resp = s.w.Transactions(max)
	}
	if resp == nil {
		resp = ResponseTransactions{}
	}
	writeJSON(w, resp)
}

// ResponseTransactionsID is the response type for the /transactions/:id
// endpoint.
type ResponseTransactionsID encodedTransaction

// override transaction marshalling to use camelCase and stringified pubkeys and
// omit empty fields
type encodedSiacoinOutput struct {
	Value      types.Currency   `json:"value"`
	UnlockHash types.UnlockHash `json:"unlockHash"`
}

type encodedPubKey struct {
	Algorithm types.Specifier
	Key       []byte
}

func (pk encodedPubKey) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(pk.Algorithm.String() + ":" + hex.EncodeToString(pk.Key))), nil
}

type encodedUnlockConditions struct {
	Timelock           types.BlockHeight `json:"timelock,omitempty"`
	PublicKeys         []encodedPubKey   `json:"publicKeys"`
	SignaturesRequired uint64            `json:"signaturesRequired"`
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

func (s *seedServer) transactionsidHandler(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var txid crypto.Hash
	if err := txid.LoadString(ps.ByName("txid")); err != nil {
		http.Error(w, "Invalid transaction ID: "+err.Error(), http.StatusBadRequest)
		return
	}
	txn, ok := s.w.Transaction(types.TransactionID(txid))
	if !ok {
		http.Error(w, "Transaction not found", http.StatusNotFound)
		return
	}
	writeJSON(w, (*ResponseTransactionsID)(unsafe.Pointer(&txn)))
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

type encodedUTXOs []struct {
	ID               types.SiacoinOutputID   `json:"ID"`
	Value            types.Currency          `json:"value"`
	UnlockConditions encodedUnlockConditions `json:"unlockConditions"`
	UnlockHash       types.UnlockHash        `json:"unlockHash"`
}

func (s *seedServer) utxosHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	var inputs []wallet.ValuedInput
	if req.FormValue("limbo") == "true" {
		inputs = s.w.LimboInputs()
	} else {
		inputs = s.w.ValuedInputs()
	}

	utxos := make(ResponseUTXOs, len(inputs))
	for i, vi := range inputs {
		utxos[i] = UTXO{
			ID:               vi.ParentID,
			Value:            vi.Value,
			UnlockConditions: vi.UnlockConditions,
			UnlockHash:       vi.UnlockConditions.UnlockHash(),
		}
	}
	writeJSON(w, *(*encodedUTXOs)(unsafe.Pointer(&utxos)))
}

// NewSeedServer returns an HTTP handler that serves the seed wallet API.
func NewSeedServer(w *wallet.SeedWallet, tp wallet.TransactionPool) http.Handler {
	s := &seedServer{
		w:  w,
		tp: tp,
	}
	mux := httprouter.New()
	mux.GET("/addresses", s.addressesHandler)
	mux.GET("/addresses/:addr", s.addressesaddrHandlerGET)
	mux.GET("/balance", s.balanceHandler)
	mux.POST("/broadcast", s.broadcastHandler)
	mux.GET("/consensus", s.consensusHandler)
	mux.PUT("/limbo/:id", s.limboHandlerPUT)
	mux.DELETE("/limbo/:id", s.limboHandlerDELETE)
	mux.POST("/nextaddress", s.nextaddressHandler)
	mux.GET("/seedindex", s.seedindexHandler)
	mux.POST("/sign", s.signHandler)
	mux.GET("/transactions", s.transactionsHandler)
	mux.GET("/transactions/:txid", s.transactionsidHandler)
	mux.GET("/utxos", s.utxosHandler)
	return mux
}
