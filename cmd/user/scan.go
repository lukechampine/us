package main

import (
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/hostdb"
)

func currencyUnits(c types.Currency) string {
	atto := types.NewCurrency64(1000000)
	if c.Cmp(atto) < 0 {
		return c.String() + " H"
	}
	mag := atto
	unit := ""
	for _, unit = range []string{"aS", "fS", "pS", "nS", "uS", "mS", "SC", "KS", "MS", "GS", "TS"} {
		if c.Cmp(mag.Mul64(1e3)) < 0 {
			break
		} else if unit != "TS" {
			mag = mag.Mul64(1e3)
		}
	}
	num := new(big.Rat).SetInt(c.Big())
	denom := new(big.Rat).SetInt(mag.Big())
	res, _ := new(big.Rat).Mul(num, denom.Inv(denom)).Float64()
	return fmt.Sprintf("%.4g %s", res, unit)
}

func lookupHost(prefix string, hosts []hostdb.HostPublicKey) (pubkey hostdb.HostPublicKey, err error) {
	if !strings.HasPrefix(prefix, "ed25519:") {
		prefix = "ed25519:" + prefix
	}
	for _, key := range hosts {
		if strings.HasPrefix(string(key), prefix) {
			if pubkey != "" {
				return "", errors.New("ambiguous pubkey")
			}
			pubkey = key
		}
	}
	if pubkey == "" {
		return "", errors.New("no host with that pubkey")
	}
	return
}

func scan(hostKeyPrefix string, bytes uint64, duration types.BlockHeight, downloads float64) error {
	c := makeClient()

	currentHeight, err := c.ChainHeight()
	if err != nil {
		currentHeight = 1e6
	}
	_, maxFee, err := c.FeeEstimate()
	if err != nil {
		return errors.Wrap(err, "could not estimate transaction fee")
	}
	hosts, err := c.Hosts()
	if err != nil {
		return errors.Wrap(err, "could not lookup host")
	}
	hostKey, err := lookupHost(hostKeyPrefix, hosts)
	if err != nil {
		return errors.Wrap(err, "could not lookup host")
	}

	start := time.Now()
	host, err := scanHost(c, hostKey)
	scanTime := time.Since(start)
	if err != nil {
		return errors.Wrap(err, "could not scan host")
	}

	cost := host.StoragePrice.Mul64(bytes).Mul64(uint64(duration)).
		Add(host.UploadBandwidthPrice.Mul64(bytes)).
		Add(host.DownloadBandwidthPrice.Mul64(bytes).MulFloat(downloads))
	hostFee := host.ContractPrice
	hostCollateral := host.Collateral.Mul64(bytes).Mul64(uint64(duration))
	if hostCollateral.Cmp(host.MaxCollateral) > 0 {
		hostCollateral = host.MaxCollateral
	}
	siafundFee := types.Tax(currentHeight, cost.Add(hostCollateral))
	txnFee := maxFee.Mul64(2000) // assume 2KB transaction size
	total := cost.Add(host.ContractPrice).Add(siafundFee).Add(txnFee)

	fmt.Printf(`Scanned host in %v

Public Key:      %v
IP Address:      %v
Latency:         %v
Data Cost:       %v
Host Fee:        %v
Siafund Fee:     %v
Transaction Fee: %v
Total:           %v
`, scanTime, hostKey, host.NetAddress, host.Latency, currencyUnits(cost), currencyUnits(hostFee),
		currencyUnits(siafundFee), currencyUnits(txnFee), currencyUnits(total))

	if !host.AcceptingContracts {
		fmt.Println("Warning: host is not accepting contracts")
	} else if host.RemainingStorage < bytes {
		fmt.Printf("Warning: host reports only %v of remaining storage\n", filesizeUnits(int64(host.RemainingStorage)))
	}

	return nil
}
