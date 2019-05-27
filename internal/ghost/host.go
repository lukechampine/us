package ghost

import (
	"encoding/hex"
	"net"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"gitlab.com/NebulousLabs/fastrand"
	"lukechampine.com/us/ed25519"
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
}

type Host struct {
	addr        modules.NetAddress
	secretKey   ed25519.PrivateKey
	listener    net.Listener
	contracts   map[types.FileContractID]*hostContract
	blockHeight types.BlockHeight
}

func (h *Host) PublicKey() hostdb.HostPublicKey {
	return hostdb.HostPublicKey("ed25519:" + hex.EncodeToString(h.secretKey.PublicKey()))
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
			if err != nil {
				println(err.Error())
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
		secretKey: ed25519.NewKeyFromSeed(fastrand.Bytes(ed25519.SeedSize)),
		contracts: make(map[types.FileContractID]*hostContract),
	}
	go h.listen()
	return h, nil
}
