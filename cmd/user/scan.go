package main

import (
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/NebulousLabs/Sia/types"
	"github.com/pkg/errors"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renter/renterutil"
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

func scanAll(n int) {
	c := makeClient()

	hosts := c.Hosts()
	if len(hosts) == 0 {
		fmt.Println("No hosts seen in blockchain yet (are you synchronized?)")
		return
	}
	fmt.Printf("Scanning %v hosts:\n", len(hosts))
	fmt.Println("Host         Latency     Storage Price    Upload Price    Download Price")
	printResult := func(h hostdb.ScannedHost) {
		fmt.Printf("%v     %4v ms    %8v/TB/mo     %8v/GB       %8v/GB\n",
			h.PublicKey.ShortKey(),
			int(h.Latency.Seconds()*1000),
			currencyUnits(h.StoragePrice.Mul64(1e12).Mul64(144*30)),
			currencyUnits(h.UploadBandwidthPrice.Mul64(1e9)),
			currencyUnits(h.DownloadBandwidthPrice.Mul64(1e9)),
		)
	}
	results := make([]hostdb.ScannedHost, 0, len(hosts))
	for r := range renterutil.ScanHosts(hosts, c.Scan) {
		if r.Error != nil || !r.Host.AcceptingContracts || r.Host.RemainingStorage < proto.SectorSize {
			continue
		}
		printResult(r.Host)
		results = append(results, r.Host)
	}
	fmt.Printf("\nSuccessfully scanned %v hosts (%.2f%% online)\n", len(results), 100*float64(len(results))/float64(len(hosts)))
	if len(results) == 0 {
		return
	}

	// print best n hosts in each category
	sort.Slice(results, func(i, j int) bool {
		return results[i].Latency < results[j].Latency
	})
	medianLatency := int(results[len(results)/2].Latency.Seconds() * 1000)
	fmt.Printf("\nLowest Latency: (median: %v ms)\n", medianLatency)
	fmt.Println("Host         Latency     Storage Price    Upload Price    Download Price")
	for i := 0; i < len(results) && i < n; i++ {
		printResult(results[i])
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].StoragePrice.Cmp(results[j].StoragePrice) < 0
	})
	medianStoragePrice := results[len(results)/2].StoragePrice.Mul64(1e12).Mul64(144 * 30)
	fmt.Printf("\nLowest Storage Price: (median: %v/TB/mo)\n", currencyUnits(medianStoragePrice))
	fmt.Println("Host         Latency     Storage Price    Upload Price    Download Price")
	for i := 0; i < len(results) && i < n; i++ {
		printResult(results[i])
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].DownloadBandwidthPrice.Cmp(results[j].UploadBandwidthPrice) < 0
	})
	medianUploadPrice := results[len(results)/2].UploadBandwidthPrice.Mul64(1e9)
	fmt.Printf("\nLowest Upload Price: (median: %v/GB)\n", currencyUnits(medianUploadPrice))
	fmt.Println("Host         Latency     Storage Price    Upload Price    Download Price")
	for i := 0; i < len(results) && i < n; i++ {
		printResult(results[i])
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].UploadBandwidthPrice.Cmp(results[j].UploadBandwidthPrice) < 0
	})
	medianDownloadPrice := results[len(results)/2].DownloadBandwidthPrice.Mul64(1e9)
	fmt.Printf("\nLowest Download Price: (median: %v/GB)\n", currencyUnits(medianDownloadPrice))
	fmt.Println("Host         Latency     Storage Price    Upload Price    Download Price")
	for i := 0; i < len(results) && i < n; i++ {
		printResult(results[i])
	}
}

func scan(hostKeyPrefix string, bytes uint64, duration types.BlockHeight, downloads float64) error {
	c := makeClient()

	hostKey, err := lookupHost(hostKeyPrefix, c.Hosts())
	if err != nil {
		return errors.Wrap(err, "could not lookup host")
	}

	// estimate RPC latency by calling ChainHeight
	start := time.Now()
	_ = c.ChainHeight()
	rpcDelay := time.Since(start)

	start = time.Now()
	host, err := c.Scan(hostKey)
	scanTime := time.Since(start) - rpcDelay
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
	siafundFee := types.Tax(c.ChainHeight(), cost.Add(hostCollateral))
	_, maxFee := c.FeeEstimate()
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
