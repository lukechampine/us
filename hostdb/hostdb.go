// Package hostdb defines types and functions relevant to scanning hosts.
package hostdb // import "lukechampine.com/us/hostdb"

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
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

// HostKeyFromPublicKey converts an ed25519.PublicKey to a HostPublicKey.
func HostKeyFromPublicKey(pk ed25519.PublicKey) HostPublicKey {
	return HostKeyFromSiaPublicKey(types.SiaPublicKey{
		Algorithm: types.SignatureEd25519,
		Key:       pk,
	})
}

// HostKeyFromSiaPublicKey converts an types.SiaPublicKey to a HostPublicKey.
func HostKeyFromSiaPublicKey(spk types.SiaPublicKey) HostPublicKey {
	return HostPublicKey(spk.String())
}

// HostSettings are the settings reported by a host.
type HostSettings struct {
	AcceptingContracts     bool               `json:"acceptingContracts"`
	MaxDownloadBatchSize   uint64             `json:"maxDownloadBatchSize"`
	MaxDuration            types.BlockHeight  `json:"maxDuration"`
	MaxReviseBatchSize     uint64             `json:"maxReviseBatchSize"`
	NetAddress             modules.NetAddress `json:"netAddress"`
	RemainingStorage       uint64             `json:"remainingStorage"`
	SectorSize             uint64             `json:"sectorSize"`
	TotalStorage           uint64             `json:"totalStorage"`
	UnlockHash             types.UnlockHash   `json:"unlockHash"`
	WindowSize             types.BlockHeight  `json:"windowSize"`
	Collateral             types.Currency     `json:"collateral"`
	MaxCollateral          types.Currency     `json:"maxCollateral"`
	BaseRPCPrice           types.Currency     `json:"baseRPCPrice"`
	ContractPrice          types.Currency     `json:"contractPrice"`
	DownloadBandwidthPrice types.Currency     `json:"downloadBandwidthPrice"`
	SectorAccessPrice      types.Currency     `json:"sectorAccessPrice"`
	StoragePrice           types.Currency     `json:"storagePrice"`
	UploadBandwidthPrice   types.Currency     `json:"uploadBandwidthPrice"`
	RevisionNumber         uint64             `json:"revisionNumber"`
	Version                string             `json:"version"`

	// RHP3 specific fields
	EphemeralAccountExpiry     time.Duration  `json:"ephemeralAccountExpiry"`
	MaxEphemeralAccountBalance types.Currency `json:"maxEphemeralAccountBalance"`
	SiaMuxPort                 string         `json:"siaMuxPort"`

	// nonstandard fields
	Make  string `json:"make"`
	Model string `json:"model"`
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
			s, err := renterhost.NewRenterSession(conn, pubkey.Ed25519())
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
