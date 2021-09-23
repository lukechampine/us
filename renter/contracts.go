package renter

import (
	"crypto/ed25519"

	"go.sia.tech/siad/types"
	"lukechampine.com/us/hostdb"
)

// A Contract identifies a unique file contract and possesses the secret key
// that can revise it.
type Contract struct {
	HostKey   hostdb.HostPublicKey
	ID        types.FileContractID
	RenterKey ed25519.PrivateKey
}
