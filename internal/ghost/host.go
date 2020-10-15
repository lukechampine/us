// Package ghost implements a barebones, ephemeral Sia host. It is used for
// testing purposes only, not hosting actual renter data on the Sia network.
package ghost

import (
	"crypto/ed25519"
	"log"
	"net"
	"sync"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/frand"
	"lukechampine.com/us/ed25519hash"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renterhost"
)

type hostContract struct {
	proofDeadline types.BlockHeight
	rev           types.FileContractRevision
	sigs          [2]types.TransactionSignature
	renterKey     types.SiaPublicKey
	sectorRoots   []crypto.Hash
	sectorData    map[crypto.Hash][renterhost.SectorSize]byte
	mu            sync.Mutex
}

type Host struct {
	addr        modules.NetAddress
	secretKey   ed25519.PrivateKey
	listener    net.Listener
	contracts   map[types.FileContractID]*hostContract
	blockHeight types.BlockHeight
	logErrs     bool
}

func (h *Host) PublicKey() hostdb.HostPublicKey {
	return hostdb.HostKeyFromPublicKey(ed25519hash.ExtractPublicKey(h.secretKey))
}

func (h *Host) Settings() hostdb.HostSettings {
	return hostdb.HostSettings{
		NetAddress:         h.addr,
		AcceptingContracts: true,
		WindowSize:         144,
		// ContractPrice:      types.SiacoinPrecision.Mul64(5),
		// StoragePrice:       types.NewCurrency64(5),
		// Collateral:         types.NewCurrency64(1),
	}
}

func (h *Host) listen() error {
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			err := h.handleConn(conn)
			if err != nil && h.logErrs {
				log.Println("ghost:", err)
			}
		}()
	}
}

func (h *Host) Close() error {
	return h.listener.Close()
}

// New returns a new host listening on the specified address.
func New(addr string) (*Host, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	h := &Host{
		addr:      modules.NetAddress(l.Addr().String()),
		listener:  l,
		secretKey: ed25519.NewKeyFromSeed(frand.Bytes(ed25519.SeedSize)),
		contracts: make(map[types.FileContractID]*hostContract),
	}
	go h.listen()
	return h, nil
}
