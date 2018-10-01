package renterutil

import (
	"context"
	"errors"
	"time"

	"lukechampine.com/us/hostdb"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/node/api/client"
	"gitlab.com/NebulousLabs/Sia/types"
)

// SiadClient wraps the siad API client. It satisfies the proto.Wallet,
// proto.TransactionPool, and renter.HostKeyResolver interfaces.
type SiadClient struct {
	siad *client.Client
}

// Consensus

func (c *SiadClient) ChainHeight() (types.BlockHeight, error) {
	cg, err := c.siad.ConsensusGet()
	return cg.Height, err
}

func (c *SiadClient) Synced() (bool, error) {
	cg, err := c.siad.ConsensusGet()
	return cg.Synced, err
}

// Transaction Pool

func (c *SiadClient) AcceptTransactionSet(txnSet []types.Transaction) error {
	if len(txnSet) == 0 {
		return errors.New("empty transaction set")
	}
	txn, parents := txnSet[len(txnSet)-1], txnSet[:len(txnSet)-1]
	return c.siad.TransactionPoolRawPost(txn, parents)
}

func (c *SiadClient) FeeEstimate() (minFee, maxFee types.Currency, err error) {
	tfg, err := c.siad.TransactionPoolFeeGet()
	return tfg.Minimum, tfg.Maximum, err
}

// Wallet

func (c *SiadClient) NewWalletAddress() (types.UnlockHash, error) {
	wag, err := c.siad.WalletAddressGet()
	return wag.Address, err
}

func (c *SiadClient) SignTransaction(txn *types.Transaction, toSign []crypto.Hash) error {
	wspr, err := c.siad.WalletSignPost(*txn, toSign)
	if err == nil {
		*txn = wspr.Transaction
	}
	return err
}

func (c *SiadClient) UnspentOutputs() ([]modules.UnspentOutput, error) {
	wug, err := c.siad.WalletUnspentGet()
	return wug.Outputs, err
}

func (c *SiadClient) UnlockConditions(addr types.UnlockHash) (types.UnlockConditions, error) {
	wucg, err := c.siad.WalletUnlockConditionsGet(addr)
	return wucg.UnlockConditions, err
}

// HostDB

func (c *SiadClient) Hosts() ([]hostdb.HostPublicKey, error) {
	hdag, err := c.siad.HostDbAllGet()
	hosts := make([]hostdb.HostPublicKey, len(hdag.Hosts))
	for i, h := range hdag.Hosts {
		hosts[i] = hostdb.HostPublicKey(h.PublicKeyString)
	}
	return hosts, err
}

func (c *SiadClient) ResolveHostKey(pubkey hostdb.HostPublicKey) (modules.NetAddress, error) {
	hhg, err := c.siad.HostDbHostsGet(pubkey.SiaPublicKey())
	return hhg.Entry.NetAddress, err
}

func (c *SiadClient) Scan(pubkey hostdb.HostPublicKey) (hostdb.ScannedHost, error) {
	hhg, err := c.siad.HostDbHostsGet(pubkey.SiaPublicKey())
	if err != nil {
		return hostdb.ScannedHost{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hostdb.Scan(ctx, hhg.Entry.NetAddress, pubkey)
}

// NewSiadClient returns a SiadClient that communicates with the siad API
// server at the specified address.
func NewSiadClient(addr, password string) *SiadClient {
	c := client.New(addr)
	c.Password = password
	return &SiadClient{siad: c}
}
