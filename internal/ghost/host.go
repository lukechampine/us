package ghost

import (
	"net"

	"golang.org/x/crypto/ed25519"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"gitlab.com/NebulousLabs/fastrand"
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

// ed25519Key implements renterhost.HashSigner with an ed25519 secret key.
type ed25519Key ed25519.PrivateKey

// SignHash implements renterhost.HashSigner.
func (e ed25519Key) SignHash(hash crypto.Hash) []byte {
	return ed25519.Sign(ed25519.PrivateKey(e), hash[:])
}

func (e ed25519Key) publicKey() types.SiaPublicKey {
	var pk crypto.PublicKey
	copy(pk[:], e[32:])
	return types.Ed25519PublicKey(pk)
}

type Host struct {
	addr        modules.NetAddress
	secretKey   ed25519Key
	listener    net.Listener
	contracts   map[types.FileContractID]*hostContract
	blockHeight types.BlockHeight
}

func (h *Host) PublicKey() hostdb.HostPublicKey {
	return hostdb.HostPublicKey(h.secretKey.publicKey().String())
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

// New returns a new host listening on a random port.
func New() (*Host, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}
	h := &Host{
		addr:      modules.NetAddress(l.Addr().String()),
		listener:  l,
		secretKey: ed25519Key(ed25519.NewKeyFromSeed(fastrand.Bytes(ed25519.SeedSize))),
		contracts: make(map[types.FileContractID]*hostContract),
	}
	go h.listen()
	return h, nil
}
