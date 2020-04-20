package renter

import (
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/ed25519"
	"lukechampine.com/us/hostdb"
)

// A Contract identifies a unique file contract and possesses the secret key
// that can revise it.
type Contract struct {
	HostKey   hostdb.HostPublicKey
	ID        types.FileContractID
	RenterKey ed25519.PrivateKey
}
