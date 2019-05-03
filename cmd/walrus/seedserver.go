package main

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
	"unsafe"

	"github.com/julienschmidt/httprouter"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/cmd/walrus/api"
	"lukechampine.com/us/wallet"
)

func writeJSON(w io.Writer, v interface{}) {
	// encode nil slices as [] instead of null
	if val := reflect.ValueOf(v); val.Kind() == reflect.Slice && val.Len() == 0 {
		w.Write([]byte("[]\n"))
		return
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")
	enc.Encode(v)
}

type seedServer struct {
	w  *wallet.SeedWallet
	tp wallet.TransactionPool
}

func (s *seedServer) addressesHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	writeJSON(w, s.w.Addresses())
}

func (s *seedServer) addressesaddrHandlerGET(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var addr types.UnlockHash
	if err := addr.LoadString(ps.ByName("addr")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	info, ok := s.w.AddressInfo(addr)
	if !ok {
		http.Error(w, "No such entry", http.StatusNotFound)
		return
	}
	writeJSON(w, api.ResponseAddressesAddr(info))
}

func (s *seedServer) balanceHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	writeJSON(w, s.w.Balance())
}

func (s *seedServer) broadcastHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	var txnSet api.RequestBroadcast
	if err := json.NewDecoder(req.Body).Decode(&txnSet); err != nil {
		http.Error(w, "Could not parse transaction: "+err.Error(), http.StatusBadRequest)
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

func (s *seedServer) consensusHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	writeJSON(w, api.ResponseConsensus{
		Height: s.w.ChainHeight(),
		CCID:   crypto.Hash(s.w.ConsensusChangeID()),
	})
}

func (s *seedServer) feeHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	median, _ := s.tp.FeeEstimation()
	writeJSON(w, median)
}

func (s *seedServer) limboHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	writeJSON(w, api.ResponseLimboUTXOs(s.w.LimboOutputs()))
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

func (s *seedServer) memosHandlerPUT(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var txid crypto.Hash
	if err := txid.LoadString(ps.ByName("txid")); err != nil {
		http.Error(w, "Invalid transaction ID: "+err.Error(), http.StatusBadRequest)
		return
	}
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "Couldn't read memo: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.w.SetMemo(types.TransactionID(txid), body)
}

func (s *seedServer) memosHandlerGET(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var txid crypto.Hash
	if err := txid.LoadString(ps.ByName("txid")); err != nil {
		http.Error(w, "Invalid transaction ID: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Write(s.w.Memo(types.TransactionID(txid)))
}

func (s *seedServer) nextaddressHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	writeJSON(w, s.w.NextAddress())
}

func (s *seedServer) seedindexHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	writeJSON(w, s.w.SeedIndex())
}

func (s *seedServer) signHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	var rs api.RequestSign
	if err := json.NewDecoder(req.Body).Decode(&rs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if err := s.w.SignTransaction(&rs.Transaction, rs.ToSign); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, (*api.ResponseSign)(unsafe.Pointer(&rs.Transaction)))
}

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

	var resp api.ResponseTransactions
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
	writeJSON(w, resp)
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
	// calculate inflow/outflow/fee
	var inflow, outflow, fee types.Currency
	for _, sco := range txn.SiacoinOutputs {
		if s.w.OwnsAddress(sco.UnlockHash) {
			inflow = inflow.Add(sco.Value)
		} else {
			outflow = outflow.Add(sco.Value)
		}
	}
	for _, c := range txn.MinerFees {
		fee = fee.Add(c)
	}
	outflow = outflow.Add(fee)
	writeJSON(w, api.ResponseTransactionsID{
		Transaction: txn,
		Inflow:      inflow,
		Outflow:     outflow,
		FeePerByte:  fee.Div64(uint64(txn.MarshalSiaSize())),
	})
}

func (s *seedServer) utxosHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	inputs := s.w.ValuedInputs()
	utxos := make(api.ResponseUTXOs, len(inputs))
	for i, vi := range inputs {
		utxos[i] = api.UTXO{
			ID:               vi.ParentID,
			Value:            vi.Value,
			UnlockConditions: vi.UnlockConditions,
			UnlockHash:       vi.UnlockConditions.UnlockHash(),
		}
	}
	writeJSON(w, utxos)
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
	mux.GET("/fee", s.feeHandler)
	mux.PUT("/limbo/:id", s.limboHandlerPUT)
	mux.GET("/limbo", s.limboHandler)
	mux.DELETE("/limbo/:id", s.limboHandlerDELETE)
	mux.PUT("/memos/:txid", s.memosHandlerPUT)
	mux.GET("/memos/:txid", s.memosHandlerGET)
	mux.POST("/nextaddress", s.nextaddressHandler)
	mux.GET("/seedindex", s.seedindexHandler)
	mux.POST("/sign", s.signHandler)
	mux.GET("/transactions", s.transactionsHandler)
	mux.GET("/transactions/:txid", s.transactionsidHandler)
	mux.GET("/utxos", s.utxosHandler)
	return mux
}
