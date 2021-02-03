package wallet

import (
	"crypto/ed25519"
	"math/big"
	"sort"
	"unsafe"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/ed25519hash"
)

// BytesPerInput is the encoded size of a SiacoinInput and corresponding
// TransactionSignature, assuming standard UnlockConditions.
const BytesPerInput = 241

// ErrInsufficientFunds is returned when the wallet does not control enough
// outputs to fund a transaction.
var ErrInsufficientFunds = errors.New("insufficient funds")

// SumOutputs returns the total value of the supplied outputs.
func SumOutputs(outputs []UnspentOutput) types.Currency {
	sum := new(big.Int)
	for _, o := range outputs {
		// sum = sum.Add(o.Value) would allocate a new value for every output;
		// instead, cheat to get a pointer to the underlying big.Int
		c := (*struct {
			i big.Int
		})(unsafe.Pointer(&o.Value))
		sum.Add(sum, &c.i)
	}
	return types.NewCurrency(sum)
}

// FundAtLeast selects a set of inputs whose total value is at least amount,
// returning the selected inputs and the resulting change, or false if the sum
// of all inputs is less than amount.
func FundAtLeast(amount types.Currency, inputs []ValuedInput) (used []ValuedInput, change types.Currency, ok bool) {
	var outputSum types.Currency
	for i, o := range inputs {
		if outputSum = outputSum.Add(o.Value); outputSum.Cmp(amount) >= 0 {
			return inputs[:i+1], outputSum.Sub(amount), true
		}
	}
	return nil, types.ZeroCurrency, amount.IsZero()
}

// FundTransaction selects a set of inputs whose total value is amount+fee,
// where fee is the estimated fee required to pay for the inputs and their
// signatures.
func FundTransaction(amount, feePerByte types.Currency, inputs []ValuedInput) (used []ValuedInput, fee, change types.Currency, ok bool) {
	// we need to fund amount+fee, but the exact fee depends on the number of
	// inputs we use...which depends on the fee. Start by getting the number of
	// inputs required to fund just the amount, then iterate until we find a
	// solution.
	used, change, ok = FundAtLeast(amount, inputs)
	if !ok {
		return nil, types.ZeroCurrency, types.ZeroCurrency, false
	}
	numInputs := len(used)
	for {
		fee = feePerByte.Mul64(BytesPerInput).Mul64(uint64(numInputs))
		used, change, ok = FundAtLeast(amount.Add(fee), inputs)
		if !ok {
			return nil, types.ZeroCurrency, types.ZeroCurrency, false
		} else if len(used) == numInputs {
			// adjusting the fee did not change the number of inputs required, so
			// we are done.
			return used, fee, change, true
		}
		numInputs = len(used)
	}
}

// AppendTransactionSignature appends a TransactionSignature to txn and signs it
// with key.
func AppendTransactionSignature(txn *types.Transaction, txnSig types.TransactionSignature, key ed25519.PrivateKey) {
	txn.TransactionSignatures = append(txn.TransactionSignatures, txnSig)
	sigIndex := len(txn.TransactionSignatures) - 1
	txn.TransactionSignatures[sigIndex].Signature = ed25519hash.Sign(key, txn.SigHash(sigIndex, types.FoundationHardforkHeight+1))
}

// UnconfirmedParents returns the parents of txn that are in limbo.
func UnconfirmedParents(txn types.Transaction, limbo []LimboTransaction) []LimboTransaction {
	// first, map each output created in a limbo transaction to its parent
	outputToParent := make(map[types.OutputID]*LimboTransaction)
	for i := range limbo {
		for j := range limbo[i].SiacoinOutputs {
			scoid := limbo[i].SiacoinOutputID(uint64(j))
			outputToParent[types.OutputID(scoid)] = &limbo[i]
		}
		for j := range limbo[i].SiafundOutputs {
			sfoid := limbo[i].SiafundOutputID(uint64(j))
			outputToParent[types.OutputID(sfoid)] = &limbo[i]
		}
	}

	// then, for each input spent in txn, if that input was created by a limbo
	// transaction, add that limbo transaction to the returned set.
	var parents []LimboTransaction
	seen := make(map[types.TransactionID]struct{})
	addParent := func(parent *LimboTransaction) {
		txid := parent.ID()
		if _, ok := seen[txid]; !ok {
			seen[txid] = struct{}{}
			parents = append(parents, *parent)
		}
	}
	for _, sci := range txn.SiacoinInputs {
		if parent, ok := outputToParent[types.OutputID(sci.ParentID)]; ok {
			addParent(parent)
		}
	}
	for _, sfi := range txn.SiafundInputs {
		if parent, ok := outputToParent[types.OutputID(sfi.ParentID)]; ok {
			addParent(parent)
		}
	}
	return parents
}

// DistributeFunds is a helper function for distributing the value in a set of
// inputs among n outputs, each containing per siacoins. It returns the minimal
// set of inputs that will fund such a transaction, along with the resulting fee
// and change. Inputs with value equal to per are ignored. If the inputs are not
// sufficient to fund n outputs, DistributeFunds returns nil.
func DistributeFunds(inputs []UnspentOutput, n int, per, feePerByte types.Currency) (ins []UnspentOutput, fee, change types.Currency) {
	// sort
	ins = append([]UnspentOutput(nil), inputs...)
	sort.Slice(ins, func(i, j int) bool {
		return ins[i].Value.Cmp(ins[j].Value) > 0
	})
	// filter
	filtered := ins[:0]
	for _, in := range ins {
		if !in.Value.Equals(per) {
			filtered = append(filtered, in)
		}
	}
	ins = filtered

	const bytesPerOutput = 64 // approximate; depends on currency size
	outputFees := feePerByte.Mul64(bytesPerOutput).Mul64(uint64(n))
	feePerInput := feePerByte.Mul64(BytesPerInput)

	// search for minimal set
	want := per.Mul64(uint64(n))
	i := sort.Search(len(ins)+1, func(i int) bool {
		fee = feePerInput.Mul64(uint64(i)).Add(outputFees)
		return SumOutputs(ins[:i]).Cmp(want.Add(fee)) >= 0
	})
	if i == len(ins)+1 {
		// insufficient funds
		return nil, types.ZeroCurrency, types.ZeroCurrency
	}
	fee = feePerInput.Mul64(uint64(i)).Add(outputFees)
	change = SumOutputs(ins[:i]).Sub(want.Add(fee))
	return ins[:i], fee, change
}
