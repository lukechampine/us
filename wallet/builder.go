package wallet

import (
	"math/big"
	"unsafe"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/ed25519"
)

// BytesPerInput is the encoded size of a SiacoinInput and corresponding
// TransactionSignature, assuming standard UnlockConditions.
const BytesPerInput = 241

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
	txn.TransactionSignatures[sigIndex].Signature = key.SignHash(txn.SigHash(sigIndex, types.ASICHardforkHeight+1))
}

// UnconfirmedParents returns the parent transactions of txn that have not yet
// appeared in the blockchain.
func UnconfirmedParents(txn types.Transaction, tp TransactionPool) []types.Transaction {
	var parents []types.Transaction
	seen := make(map[types.TransactionID]struct{})

sciLoop:
	for _, sci := range txn.SiacoinInputs {
		uh := sci.UnlockConditions.UnlockHash()
		parentSet := tp.TransactionSet(crypto.Hash(sci.ParentID))
		for _, parentTxn := range parentSet {
			txid := parentTxn.ID()
			if _, ok := seen[txid]; ok {
				continue
			}
			seen[txid] = struct{}{}
			parents = append(parents, parentTxn)

			// If this is the transaction that created the input, stop here.
			// There may be additional children in the parentSet, but we don't
			// need (or want) to include them.
			for i, sco := range parentTxn.SiacoinOutputs {
				// check UnlockHash first; calculating IDs is expensive
				if sco.UnlockHash == uh && parentTxn.SiacoinOutputID(uint64(i)) == sci.ParentID {
					continue sciLoop
				}
			}
		}
	}

sfiLoop:
	for _, sfi := range txn.SiafundInputs {
		uh := sfi.UnlockConditions.UnlockHash()
		parentSet := tp.TransactionSet(crypto.Hash(sfi.ParentID))
		for _, parentTxn := range parentSet {
			txid := parentTxn.ID()
			if _, ok := seen[txid]; ok {
				continue
			}
			seen[txid] = struct{}{}
			parents = append(parents, parentTxn)
			for i, sco := range parentTxn.SiacoinOutputs {
				if sco.UnlockHash == uh && parentTxn.SiafundOutputID(uint64(i)) == sfi.ParentID {
					continue sfiLoop
				}
			}
		}
	}

	return parents
}
