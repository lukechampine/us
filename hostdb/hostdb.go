// Package hostdb defines types and functions relevant to scanning hosts.
package hostdb

import (
	"context"
	"encoding/hex"
	"net"
	"strings"
	"time"

	"github.com/NebulousLabs/Sia/crypto"
	"github.com/NebulousLabs/Sia/encoding"
	"github.com/NebulousLabs/Sia/modules"
	"github.com/NebulousLabs/Sia/types"
	"github.com/pkg/errors"
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
	key := hpk.Key()
	return key[:8]
}

// Ed25519 returns the HostPublicKey as a crypto.PublicKey. The returned key
// is obviously invalid if hpk is not a Ed25519 key.
func (hpk HostPublicKey) Ed25519() (cpk crypto.PublicKey) {
	hex.Decode(cpk[:], []byte(hpk.Key()))
	return
}

// SiaPublicKey returns the HostPublicKey as a types.SiaPublicKey.
func (hpk HostPublicKey) SiaPublicKey() (spk types.SiaPublicKey) {
	specLen := strings.IndexByte(string(hpk), ':')
	if specLen < 0 {
		return
	}
	copy(spk.Algorithm[:], hpk[:specLen])
	spk.Key, _ = hex.DecodeString(string(hpk[specLen+1:]))
	return
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
	ContractPrice          types.Currency     `json:"contractPrice"`
	DownloadBandwidthPrice types.Currency     `json:"downloadBandwidthPrice"`
	StoragePrice           types.Currency     `json:"storagePrice"`
	UploadBandwidthPrice   types.Currency     `json:"uploadBandwidthPrice"`
	RevisionNumber         uint64             `json:"revisionNumber"`
	Version                string             `json:"version"`
}

// ScannedHost groups a host's settings with its public key and other scan-
// related metrics.
type ScannedHost struct {
	HostSettings
	PublicKey HostPublicKey `json:"publicKey"`
	Latency   time.Duration `json:"latency"`
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
		err = encoding.WriteObject(conn, modules.RPCSettings)
		if err != nil {
			ch <- res{host, errors.Wrap(err, "could not write RPC header")}
			return
		}
		const maxSettingsLen = 2e3
		err = crypto.ReadSignedObject(conn, &host.HostSettings, maxSettingsLen, pubkey.Ed25519())
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
