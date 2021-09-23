package renterutil

import (
	"errors"
	"math"
	"reflect"
	"sort"
	"strings"

	"go.sia.tech/siad/crypto"
	"go.sia.tech/siad/modules"
	"go.sia.tech/siad/node/api/client"
	"go.sia.tech/siad/types"
	"lukechampine.com/frand"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/wallet"
)

// ErrNoHostAnnouncement is returned when a host announcement cannot be found.
var ErrNoHostAnnouncement = errors.New("host announcement not found")

// SiadClient wraps the siad API client. It satisfies the proto.Wallet,
// proto.TransactionPool, and renter.HostKeyResolver interfaces. The
// proto.Wallet methods require that the wallet is unlocked.
type SiadClient struct {
	siad *client.Client
}

// ChainHeight returns the current block height.
func (c *SiadClient) ChainHeight() (types.BlockHeight, error) {
	cg, err := c.siad.ConsensusGet()
	return cg.Height, err
}

// Synced returns whether the siad node believes it is fully synchronized with
// the rest of the network.
func (c *SiadClient) Synced() (bool, error) {
	cg, err := c.siad.ConsensusGet()
	return cg.Synced, err
}

// AcceptTransactionSet submits a transaction set to the transaction pool,
// where it will be broadcast to other peers.
func (c *SiadClient) AcceptTransactionSet(txnSet []types.Transaction) error {
	if len(txnSet) == 0 {
		return errors.New("empty transaction set")
	}
	txn, parents := txnSet[len(txnSet)-1], txnSet[:len(txnSet)-1]
	return c.siad.TransactionPoolRawPost(txn, parents)
}

// FeeEstimate returns the current estimate for transaction fees, in Hastings
// per byte.
func (c *SiadClient) FeeEstimate() (minFee, maxFee types.Currency, err error) {
	tfg, err := c.siad.TransactionPoolFeeGet()
	return tfg.Minimum, tfg.Maximum, err
}

// Address returns an address derived from the wallet's seed.
func (c *SiadClient) Address() (types.UnlockHash, error) {
	wag, err := c.siad.WalletAddressGet()
	return wag.Address, err
}

// FundTransaction adds the specified signatures to the transaction using
// private keys known to the wallet.
func (c *SiadClient) FundTransaction(txn *types.Transaction, amount types.Currency) ([]crypto.Hash, func(), error) {
	if amount.IsZero() {
		return nil, func() {}, nil
	}

	wug, err := c.siad.WalletUnspentGet()
	if err != nil {
		return nil, nil, err
	}
	// filter out siafund outputs
	outputs := wug.Outputs[:0]
	for _, o := range wug.Outputs {
		if o.FundType == types.SpecifierSiacoinOutput {
			outputs = append(outputs, o)
		}
	}
	// compute balances
	var balance, confirmedBalance types.Currency
	for _, o := range wug.Outputs {
		balance = balance.Add(o.Value)
		if o.ConfirmationHeight != math.MaxUint64 {
			confirmedBalance = confirmedBalance.Add(o.Value)
		}
	}
	if balance.Cmp(amount) < 0 {
		return nil, nil, wallet.ErrInsufficientFunds
	} else if confirmedBalance.Cmp(amount) >= 0 {
		// sufficient confirmed balance; filter out unconfirmed outputs
		outputs = outputs[:0]
		for _, o := range wug.Outputs {
			if o.FundType == types.SpecifierSiacoinOutput && o.ConfirmationHeight != math.MaxUint64 {
				outputs = append(outputs, o)
			}
		}
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
		wucg, err := c.siad.WalletUnlockConditionsGet(o.UnlockHash)
		if err != nil {
			return nil, nil, err
		}
		txn.SiacoinInputs = append(txn.SiacoinInputs, types.SiacoinInput{
			ParentID:         types.SiacoinOutputID(o.ID),
			UnlockConditions: wucg.UnlockConditions,
		})
		txn.TransactionSignatures = append(txn.TransactionSignatures, wallet.StandardTransactionSignature(crypto.Hash(o.ID)))
		toSign = append(toSign, crypto.Hash(o.ID))
	}
	// add change output if needed
	if change := outputSum.Sub(amount); !change.IsZero() {
		changeAddr, err := c.Address()
		if err != nil {
			return nil, nil, err
		}
		txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{
			UnlockHash: changeAddr,
			Value:      change,
		})
	}
	return toSign, func() {}, nil // TODO
}

// SignTransaction adds the specified signatures to the transaction using
// private keys known to the wallet.
func (c *SiadClient) SignTransaction(txn *types.Transaction, toSign []crypto.Hash) error {
	wspr, err := c.siad.WalletSignPost(*txn, toSign)
	if err == nil {
		*txn = wspr.Transaction
	}
	return err
}

// UnconfirmedParents returns any currently-unconfirmed parents of the specified
// transaction.
func (c *SiadClient) UnconfirmedParents(txn types.Transaction) ([]types.Transaction, error) {
	tptg, err := c.siad.TransactionPoolTransactionsGet()
	if err != nil {
		return nil, err
	}
	// see wallet.UnconfirmedParents
	outputToParent := make(map[types.OutputID]*types.Transaction)
	for i, txn := range tptg.Transactions {
		for j := range txn.SiacoinOutputs {
			scoid := txn.SiacoinOutputID(uint64(j))
			outputToParent[types.OutputID(scoid)] = &tptg.Transactions[i]
		}
	}
	var parents []types.Transaction
	seen := make(map[types.TransactionID]struct{})
	addParent := func(parent *types.Transaction) {
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
	return parents, nil
}

// HostDB

// LookupHost returns the host public key matching the specified prefix.
func (c *SiadClient) LookupHost(prefix string) (hostdb.HostPublicKey, error) {
	if !strings.HasPrefix(prefix, "ed25519:") {
		prefix = "ed25519:" + prefix
	}
	hdag, err := c.siad.HostDbAllGet()
	if err != nil {
		return "", err
	}
	var hpk hostdb.HostPublicKey
	for i := range hdag.Hosts {
		key := hostdb.HostPublicKey(hdag.Hosts[i].PublicKeyString)
		if strings.HasPrefix(string(key), prefix) {
			if hpk != "" {
				return "", errors.New("ambiguous pubkey")
			}
			hpk = key
		}
	}
	if hpk == "" {
		return "", errors.New("no host with that pubkey")
	}
	return hpk, nil
}

// ResolveHostKey resolves a host public key to that host's most recently
// announced network address.
func (c *SiadClient) ResolveHostKey(pubkey hostdb.HostPublicKey) (modules.NetAddress, error) {
	hhg, err := c.siad.HostDbHostsGet(pubkey.SiaPublicKey())
	if err != nil && strings.Contains(err.Error(), "requested host does not exist") {
		return "", ErrNoHostAnnouncement
	}
	return hhg.Entry.NetAddress, err
}

// NewSiadClient returns a SiadClient that communicates with the siad API
// server at the specified address.
func NewSiadClient(addr, password string) *SiadClient {
	c := client.New(client.Options{
		Address:   addr,
		Password:  password,
		UserAgent: "Sia-Agent",
	})
	return &SiadClient{siad: c}
}

// verify that clients satisfy their intended interfaces
var (
	_ interface {
		proto.Wallet
		proto.TransactionPool
		renter.HostKeyResolver
	} = (*SiadClient)(nil)
)
