package main

import (
	"context"
	"time"

	"github.com/lukechampine/us/hostdb"

	"github.com/NebulousLabs/Sia/modules"
	"github.com/NebulousLabs/Sia/node/api/client"
	"github.com/NebulousLabs/Sia/types"
)

type siadClient struct {
	siad *client.Client
}

// Consensus

func (c *siadClient) ChainHeight() types.BlockHeight {
	cg, err := c.siad.ConsensusGet()
	check("Couldn't get consensus status:", err)
	return cg.Height
}

func (c *siadClient) Synced() bool {
	cg, err := c.siad.ConsensusGet()
	check("Couldn't get consensus status:", err)
	return cg.Synced
}

// Transaction Pool

func (c *siadClient) AcceptTransactionSet(txnSet []types.Transaction) error {
	parents, txn := txnSet[:len(txnSet)-1], txnSet[len(txnSet)-1]
	return c.siad.TransactionpoolRawPost(parents, txn)
}

func (c *siadClient) FeeEstimate() (minFee, maxFee types.Currency) {
	tfg, err := c.siad.TransactionPoolFeeGet()
	check("Couldn't get transaction pool fees:", err)
	return tfg.Minimum, tfg.Maximum
}

// Wallet

func (c *siadClient) NewWalletAddress() (types.UnlockHash, error) {
	wag, err := c.siad.WalletAddressGet()
	return wag.Address, err
}

func (c *siadClient) SignTransaction(txn *types.Transaction, toSign map[types.OutputID]types.UnlockHash) error {
	wspr, err := c.siad.WalletSignPost(*txn, toSign)
	if err == nil {
		*txn = wspr.Transaction
	}
	return err
}

func (c *siadClient) SpendableOutputs() []modules.SpendableOutput {
	wug, err := c.siad.WalletUnspentGet()
	check("Could not get spendable outputs:", err)
	return wug.Outputs
}

// HostDB

func (c *siadClient) Hosts() []hostdb.HostPublicKey {
	hdag, err := c.siad.HostDbAllGet()
	check("Could not get active hosts:", err)
	hosts := make([]hostdb.HostPublicKey, len(hdag.Hosts))
	for i, h := range hdag.Hosts {
		hosts[i] = hostdb.HostPublicKey(h.PublicKeyString)
	}
	return hosts
}

func (c *siadClient) Scan(pubkey hostdb.HostPublicKey) (hostdb.ScannedHost, error) {
	hhg, err := c.siad.HostDbHostsGet(string(pubkey))
	check("Could not lookup host:", err) // TODO: what if host does not exist?
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hostdb.Scan(ctx, hhg.Entry.NetAddress, pubkey)
}

func makeClient() *siadClient {
	c := client.New(config.SiadAddr)
	c.Password = config.SiadPassword
	return &siadClient{c}
}
