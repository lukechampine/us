// Package hostdb defines types and functions relevant to scanning hosts.
package hostdb // import "lukechampine.com/us/hostdb"

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/ed25519"
	"lukechampine.com/us/renterhost"
)

// A HostPublicKey is the public key announced on the blockchain by a host. A
// HostPublicKey can be assumed to uniquely identify a host. Hosts should
// always be identified by their public key, since other identifying
// information (like a host's current IP address) may change at a later time.
//
// The format of a HostPublicKey is:
//
//    specifier:keydata
//
// Where specifier identifies the signature scheme used and keydata contains
// the hex-encoded bytes of the actual key. Currently, all public keys on Sia
// use the Ed25519 signature scheme, specified as "ed25519".
type HostPublicKey string

// Key returns the keydata portion of a HostPublicKey.
func (hpk HostPublicKey) Key() string {
	specLen := strings.IndexByte(string(hpk), ':')
	if specLen < 0 {
		return ""
	}
	return string(hpk[specLen+1:])
}

// ShortKey returns the keydata portion of a HostPublicKey, truncated to 8
// characters. This is 32 bits of entropy, which is sufficient to prevent
// collisions in typical usage scenarios. A ShortKey is the preferred way to
// reference a HostPublicKey in user interfaces.
func (hpk HostPublicKey) ShortKey() string {
	return hpk.Key()[:8]
}

// Ed25519 returns the HostPublicKey as an ed25519.PublicKey. The returned key
// is invalid if hpk is not a Ed25519 key.
func (hpk HostPublicKey) Ed25519() ed25519.PublicKey {
	pk, _ := hex.DecodeString(hpk.Key())
	return ed25519.PublicKey(pk)
}

// SiaPublicKey returns the HostPublicKey as a types.SiaPublicKey.
func (hpk HostPublicKey) SiaPublicKey() (spk types.SiaPublicKey) {
	spk.LoadString(string(hpk))
	return
}

// VerifyHash verifies that hash was signed by the public key.
func (hpk HostPublicKey) VerifyHash(hash crypto.Hash, sig []byte) bool {
	if !strings.HasPrefix(string(hpk), "ed25519") {
		panic("unsupported signature algorithm")
	}
	return hpk.Ed25519().VerifyHash(hash, sig)
}

// HostSettings are the settings reported by a host.
type HostSettings struct {
	AcceptingContracts     bool
	MaxDownloadBatchSize   uint64
	MaxDuration            types.BlockHeight
	MaxReviseBatchSize     uint64
	NetAddress             modules.NetAddress
	RemainingStorage       uint64
	SectorSize             uint64
	TotalStorage           uint64
	UnlockHash             types.UnlockHash
	WindowSize             types.BlockHeight
	Collateral             types.Currency
	MaxCollateral          types.Currency
	BaseRPCPrice           types.Currency
	ContractPrice          types.Currency
	DownloadBandwidthPrice types.Currency
	SectorAccessPrice      types.Currency
	StoragePrice           types.Currency
	UploadBandwidthPrice   types.Currency
	RevisionNumber         uint64
	Version                string
}

// ScannedHost groups a host's settings with its public key and other scan-
// related metrics.
type ScannedHost struct {
	HostSettings
	PublicKey HostPublicKey
	Latency   time.Duration
}

// Scan dials the host with the given NetAddress and public key and requests
// its settings.
func Scan(ctx context.Context, addr modules.NetAddress, pubkey HostPublicKey) (host ScannedHost, err error) {
	host.PublicKey = pubkey
	dialStart := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", string(addr))
	host.Latency = time.Since(dialStart)
	if err != nil {
		return host, err
	}
	defer conn.Close()
	type res struct {
		host ScannedHost
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		err := func() error {
			s, err := renterhost.NewRenterSession(conn, pubkey)
			if err != nil {
				return errors.Wrap(err, "could not initiate RPC session")
			}
			defer s.Close()
			var resp renterhost.RPCSettingsResponse
			if err := s.WriteRequest(renterhost.RPCSettingsID, nil); err != nil {
				return err
			} else if err := s.ReadResponse(&resp, 4096); err != nil {
				return err
			} else if err := json.Unmarshal(resp.Settings, &host.HostSettings); err != nil {
				return err
			}
			return nil
		}()
		ch <- res{host, errors.Wrap(err, "could not read signed host settings")}
	}()
	select {
	case <-ctx.Done():
		conn.Close()
		return host, ctx.Err()
	case r := <-ch:
		return r.host, r.err
	}
}
