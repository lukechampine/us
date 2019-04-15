package renterutil

import (
	"context"
	"io/ioutil"
	"runtime"
	"sync"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/fastrand"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renterhost"
)

// A CheckupResult contains the result of a host checkup.
type CheckupResult struct {
	Host      hostdb.HostPublicKey
	Latency   time.Duration
	Bandwidth float64 // Mbps
	Error     error
}

// Checkup attempts to download a random slice from each host storing the
// data referenced by m. It reports whether the download was successful, along
// with network metrics.
func Checkup(contracts renter.ContractSet, m *renter.MetaFile, hkr renter.HostKeyResolver) <-chan CheckupResult {
	results := make(chan CheckupResult, len(m.Hosts))
	go checkup(results, contracts, m, hkr)
	return results
}

func checkup(results chan<- CheckupResult, contracts renter.ContractSet, m *renter.MetaFile, hkr renter.HostKeyResolver) {
	defer close(results)
	for _, hostKey := range m.Hosts {
		res := CheckupResult{Host: hostKey}

		contract, ok := contracts[hostKey]
		if !ok {
			res.Error = errors.Errorf("no contract for host")
			results <- res
			continue
		}

		// load shard slices
		slices, err := renter.ReadShard(m.ShardPath(hostKey))
		if err != nil {
			res.Error = errors.Wrap(err, "could not load shard slices")
			results <- res
			continue
		} else if len(slices) == 0 {
			res.Error = errors.New("no slices stored on host")
			results <- res
			continue
		}

		// get host IP
		hostIP, err := hkr.ResolveHostKey(hostKey)
		if err != nil {
			res.Error = errors.Wrap(err, "could not resolve host key")
			results <- res
			continue
		}

		// TODO: record settings in CheckupResult, and refuse to continue if
		// download price is too high.

		// create downloader
		start := time.Now()
		s, err := proto.NewSession(hostIP, contract, 0)
		res.Latency = time.Since(start)
		if err != nil {
			res.Error = err
			results <- res
			continue
		}
		h := renter.ShardDownloader{
			Downloader: s,
			Slices:     slices,
			Key:        m.MasterKey,
		}

		// download a random slice
		chunk := int64(fastrand.Intn(len(slices)))
		start = time.Now()
		data, err := h.DownloadAndDecrypt(chunk)
		bandTime := time.Since(start)
		h.Close()
		if err != nil {
			res.Error = errors.Wrap(err, "could not download slice")
			results <- res
			continue
		}

		res.Bandwidth = (float64(len(data)) * 8 / 1e6) / bandTime.Seconds()
		results <- res
	}
}

// CheckupContract attempts to download a random sector from the specified
// contract. It reports whether the download was successful, along with
// network metrics. Note that unlike Checkup, CheckupContracts cannot verify
// the integrity of the downloaded sector.
func CheckupContract(contract *renter.Contract, hkr renter.HostKeyResolver) CheckupResult {
	hostKey := contract.HostKey()
	res := CheckupResult{Host: hostKey}

	numSectors := int(contract.Revision().Revision.NewFileSize / renterhost.SectorSize)
	if numSectors == 0 {
		res.Error = errors.New("no sectors stored on host")
		return res
	}

	// get host IP
	hostIP, err := hkr.ResolveHostKey(hostKey)
	if err != nil {
		res.Error = errors.Wrap(err, "could not resolve host key")
		return res
	}

	// TODO: record settings in CheckupResult, and refuse to continue if
	// download is too high.

	// create downloader
	start := time.Now()
	s, err := proto.NewSession(hostIP, contract, 0)
	res.Latency = time.Since(start)
	if err != nil {
		res.Error = errors.Wrap(err, "could not initiate download protocol")
		return res
	}
	defer s.Close()

	// request a random sector root
	roots, err := s.SectorRoots(fastrand.Intn(numSectors), 1)
	if err != nil {
		res.Error = errors.Wrap(err, "could not get a sector to test")
		return res
	}
	root := roots[0]

	// download the sector
	start = time.Now()
	err = s.Read(ioutil.Discard, []renterhost.RPCReadRequestSection{{
		MerkleRoot: root,
		Offset:     0,
		Length:     renterhost.SectorSize,
	}})
	bandTime := time.Since(start)
	if err != nil {
		res.Error = errors.Wrap(err, "could not download sector")
		return res
	}

	res.Bandwidth = (renterhost.SectorSize * 8 / 1e6) / bandTime.Seconds()
	return res
}

// A ScanResult contains the result of a host scan.
type ScanResult struct {
	Host  hostdb.ScannedHost
	Error error
}

// ScanHosts scans the provided hosts in parallel and reports their settings, along
// with network metrics.
func ScanHosts(hosts []hostdb.HostPublicKey, hkr renter.HostKeyResolver) <-chan ScanResult {
	results := make(chan ScanResult, runtime.NumCPU())
	go scanHosts(results, hosts, hkr)
	return results
}

func scanHosts(results chan<- ScanResult, hosts []hostdb.HostPublicKey, hkr renter.HostKeyResolver) {
	type scanRequest struct {
		pubkey hostdb.HostPublicKey
		hostIP modules.NetAddress
	}
	reqChan := make(chan scanRequest)
	var wg sync.WaitGroup
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range reqChan {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				host, err := hostdb.Scan(ctx, req.hostIP, req.pubkey)
				cancel()
				results <- ScanResult{
					Host:  host,
					Error: err,
				}
			}
		}()
	}
	for _, pubkey := range hosts {
		hostIP, err := hkr.ResolveHostKey(pubkey)
		if err != nil {
			results <- ScanResult{Error: err}
			continue
		}
		reqChan <- scanRequest{
			pubkey: pubkey,
			hostIP: hostIP,
		}
	}
	close(reqChan)
	wg.Wait()
	close(results)
}
