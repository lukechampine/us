package ghost

import (
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
)

type StubWallet struct{}

func (StubWallet) NewWalletAddress() (uh types.UnlockHash, err error)                       { return }
func (StubWallet) SignTransaction(*types.Transaction, []crypto.Hash) (err error)            { return }
func (StubWallet) UnspentOutputs(bool) (us []modules.UnspentOutput, err error)              { return }
func (StubWallet) UnconfirmedParents(types.Transaction) (ps []types.Transaction, err error) { return }
func (StubWallet) UnlockConditions(types.UnlockHash) (uc types.UnlockConditions, err error) { return }

type StubTpool struct{}

func (StubTpool) AcceptTransactionSet([]types.Transaction) (err error) { return }
func (StubTpool) FeeEstimate() (min, max types.Currency, err error)    { return }
