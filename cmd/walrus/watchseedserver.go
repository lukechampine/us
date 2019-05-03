package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/julienschmidt/httprouter"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/encoding"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/cmd/walrus/api"
	"lukechampine.com/us/wallet"
)

type watchSeedServer struct {
	w  *wallet.WatchOnlyWallet
	tp wallet.TransactionPool
}

func (s *watchSeedServer) getInfo(addr types.UnlockHash) (wallet.SeedAddressInfo, bool) {
	info := s.w.AddressInfo(addr)
	if info == nil {
		return wallet.SeedAddressInfo{}, false
	}
	var entry wallet.SeedAddressInfo
	if err := encoding.Unmarshal(info, &entry); err != nil {
		panic(err)
	}
	return entry, true
}

func (s *watchSeedServer) addressesHandlerGET(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	writeJSON(w, s.w.Addresses())
}

func (s *watchSeedServer) addressesHandlerPOST(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var info api.RequestAddresses
	if err := json.NewDecoder(req.Body).Decode(&info); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	addr := info.UnlockConditions.UnlockHash()
	s.w.AddAddress(addr, encoding.Marshal(info))
	writeJSON(w, addr)
}

func (s *watchSeedServer) addressesaddrHandlerGET(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var addr types.UnlockHash
	if err := addr.LoadString(ps.ByName("addr")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	info, ok := s.getInfo(addr)
	if !ok {
		http.Error(w, "No such entry", http.StatusNoContent)
		return
	}
	writeJSON(w, info)
}

func (s *watchSeedServer) addressesaddrHandlerDELETE(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var addr types.UnlockHash
	if err := addr.LoadString(ps.ByName("addr")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.w.RemoveAddress(addr)
}

func (s *watchSeedServer) balanceHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	writeJSON(w, s.w.Balance())
}

func (s *watchSeedServer) broadcastHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	var txnSet api.RequestBroadcast
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
	if err := s.tp.AcceptTransactionSet(append(parents, txnSet...)); err != nil && err != modules.ErrDuplicateTransactionSet {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// mark all wallet-owned inputs as spent
	for _, txn := range txnSet {
		for _, sci := range txn.SiacoinInputs {
			if s.w.OwnsAddress(sci.UnlockConditions.UnlockHash()) {
				s.w.MarkSpent(sci.ParentID, true)
			}
		}
	}
}

func (s *watchSeedServer) consensusHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	writeJSON(w, api.ResponseConsensus{
		Height: s.w.ChainHeight(),
		CCID:   crypto.Hash(s.w.ConsensusChangeID()),
	})
}

func (s *watchSeedServer) feeHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	median, _ := s.tp.FeeEstimation()
	writeJSON(w, median)
}

func (s *watchSeedServer) limboHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	writeJSON(w, api.ResponseLimboUTXOs(s.w.LimboOutputs()))
}

func (s *watchSeedServer) limboHandlerPUT(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var id crypto.Hash
	if err := id.LoadString(ps.ByName("id")); err != nil {
		http.Error(w, "Invalid ID: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.w.MarkSpent(types.SiacoinOutputID(id), true)
}

func (s *watchSeedServer) limboHandlerDELETE(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var id crypto.Hash
	if err := id.LoadString(ps.ByName("id")); err != nil {
		http.Error(w, "Invalid ID: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.w.MarkSpent(types.SiacoinOutputID(id), false)
}

func (s *watchSeedServer) memosHandlerPUT(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
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

func (s *watchSeedServer) memosHandlerGET(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var txid crypto.Hash
	if err := txid.LoadString(ps.ByName("txid")); err != nil {
		http.Error(w, "Invalid transaction ID: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Write(s.w.Memo(types.TransactionID(txid)))
}

func (s *watchSeedServer) transactionsHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
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

func (s *watchSeedServer) transactionsidHandler(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
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

func (s *watchSeedServer) utxosHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	outputs := s.w.UnspentOutputs()
	utxos := make(api.ResponseSeedUTXOs, len(outputs))
	for i, o := range outputs {
		info, ok := s.getInfo(o.UnlockHash)
		if !ok {
			panic("missing info for " + o.UnlockHash.String())
		}
		utxos[i] = api.SeedUTXO{
			UTXO: api.UTXO{
				ID:               o.ID,
				Value:            o.Value,
				UnlockConditions: info.UnlockConditions,
				UnlockHash:       o.UnlockHash,
			},
			KeyIndex: info.KeyIndex,
		}
	}
	writeJSON(w, utxos)
}

// NewWatchSeedServer returns an HTTP handler that serves the watch-only
// seed-based wallet API.
func NewWatchSeedServer(w *wallet.WatchOnlyWallet, tp wallet.TransactionPool) http.Handler {
	s := &watchSeedServer{
		w:  w,
		tp: tp,
	}
	mux := httprouter.New()
	mux.GET("/addresses", s.addressesHandlerGET)
	mux.POST("/addresses", s.addressesHandlerPOST)
	mux.GET("/addresses/:addr", s.addressesaddrHandlerGET)
	mux.DELETE("/addresses/:addr", s.addressesaddrHandlerDELETE)
	mux.GET("/balance", s.balanceHandler)
	mux.POST("/broadcast", s.broadcastHandler)
	mux.GET("/consensus", s.consensusHandler)
	mux.GET("/fee", s.feeHandler)
	mux.GET("/limbo", s.limboHandler)
	mux.PUT("/limbo/:id", s.limboHandlerPUT)
	mux.DELETE("/limbo/:id", s.limboHandlerDELETE)
	mux.PUT("/memos/:txid", s.memosHandlerPUT)
	mux.GET("/memos/:txid", s.memosHandlerGET)
	mux.GET("/transactions", s.transactionsHandler)
	mux.GET("/transactions/:txid", s.transactionsidHandler)
	mux.GET("/utxos", s.utxosHandler)
	return mux
}
