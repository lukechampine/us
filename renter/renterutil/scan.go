package renterutil

import (
	"runtime"
	"sync"
	"time"

	"gitlab.com/NebulousLabs/fastrand"

	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/proto"

	"github.com/pkg/errors"
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
func Checkup(contracts renter.ContractSet, m *renter.MetaFile, scan renter.ScanFn) <-chan CheckupResult {
	results := make(chan CheckupResult, len(m.Hosts))
	go checkup(results, contracts, m, scan)
	return results
}

func checkup(results chan<- CheckupResult, contracts renter.ContractSet, m *renter.MetaFile, scan renter.ScanFn) {
	defer close(results)
	for i, hostKey := range m.Hosts {
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

		// get host entry
		host, err := scan(hostKey)
		if err != nil {
			res.Error = errors.Wrap(err, "could not scan host")
			results <- res
			continue
		}

		// TODO: record settings in CheckupResult, and refuse to continue if
		// download is too high.

		// create downloader
		start := time.Now()
		d, err := proto.NewDownloader(host, contract)
		res.Latency = time.Since(start)
		if err != nil {
			res.Error = err
			results <- res
			continue
		}
		h := renter.ShardDownloader{
			Downloader: d,
			Slices:     slices,
			Key:        m.EncryptionKey(i),
		}

		// download a random slice
		chunk := int64(fastrand.Intn(len(slices)))
		start = time.Now()
		data, err := h.DownloadAndDecrypt(chunk)
		bandTime := time.Since(start)
		d.Close()
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
func CheckupContract(contract *renter.Contract, scan renter.ScanFn) CheckupResult {
	hostKey := contract.HostKey()
	res := CheckupResult{Host: hostKey}

	if contract.NumSectors() == 0 {
		res.Error = errors.New("no sectors stored on host")
		return res
	}

	// get host entry
	host, err := scan(hostKey)
	if err != nil {
		res.Error = errors.Wrap(err, "could not scan host")
		return res
	}

	// TODO: record settings in CheckupResult, and refuse to continue if
	// download is too high.

	// create downloader
	start := time.Now()
	d, err := proto.NewDownloader(host, contract)
	res.Latency = time.Since(start)
	if err != nil {
		res.Error = errors.Wrap(err, "could not initiate download protocol")
		return res
	}

	// download a random sector
	root, err := contract.SectorRoot(fastrand.Intn(contract.NumSectors()))
	if err != nil {
		res.Error = errors.Wrap(err, "could not get a sector to test")
		return res
	}
	var sector [proto.SectorSize]byte
	start = time.Now()
	err = d.Sector(&sector, root)
	bandTime := time.Since(start)
	d.Close()
	if err != nil {
		res.Error = errors.Wrap(err, "could not download sector")
		return res
	}

	res.Bandwidth = (proto.SectorSize * 8 / 1e6) / bandTime.Seconds()
	return res
}

// A ScanResult contains the result of a host scan.
type ScanResult struct {
	Host  hostdb.ScannedHost
	Error error
}

// ScanHosts scans the provided hosts in parallel and reports their settings, along
// with network metrics.
func ScanHosts(hosts []hostdb.HostPublicKey, scan renter.ScanFn) <-chan ScanResult {
	results := make(chan ScanResult, runtime.NumCPU())
	go scanHosts(results, hosts, scan)
	return results
}

func scanHosts(results chan<- ScanResult, hosts []hostdb.HostPublicKey, scan renter.ScanFn) {
	hostChan := make(chan hostdb.HostPublicKey)
	var wg sync.WaitGroup
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range hostChan {
				host, err := scan(h)
				results <- ScanResult{
					Host:  host,
					Error: err,
				}
			}
		}()
	}
	for i := range hosts {
		hostChan <- hosts[i]
	}
	close(hostChan)
	wg.Wait()
	close(results)
}
