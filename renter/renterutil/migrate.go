package renterutil

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/proto"

	"github.com/NebulousLabs/Sia/types"
	"github.com/pkg/errors"
)

// A MigrateSkipUpdate indicates that a host will not be migrated to.
type MigrateSkipUpdate struct {
	Host hostdb.HostPublicKey
	Err  error
}

// MigrateFile uploads file shards to a new set of hosts. The shards are
// retrieved by erasure-encoding f.
func MigrateFile(f *os.File, newcontracts renter.ContractSet, m *renter.MetaFile, scan renter.ScanFn, height types.BlockHeight) *Operation {
	op := newOperation()
	if len(newcontracts) != len(m.Hosts) {
		op.die(errors.New("new contract set must match size of previous contract set"))
		return op
	}
	migrations := computeMigrations(newcontracts, m.Hosts)
	if len(migrations) == 0 {
		op.die(nil)
		return op
	}
	go migrateFile(op, f, newcontracts, migrations, m, scan, height)
	return op
}

// MigrateDirFile runs the MigrateFile process on each meta file in a
// directory, using it's corresponding file on disk. The directory structure
// of the files and metafiles must match.
func MigrateDirFile(newcontracts renter.ContractSet, nextFile FileIter, scan renter.ScanFn, height types.BlockHeight) *Operation {
	op := newOperation()
	go migrateDirFile(op, newcontracts, nextFile, scan, height)
	return op
}

// MigrateDirect transfers file shards from one set of hosts to another. Each
// "old" host is paired with a "new" host, and the shards of each old host are
// downloaded and reuploaded to their corresponding new host.
//
// Unlike the other Migrate functions, MigrateDirect will continue migrating
// even if some old hosts become unreachable.
func MigrateDirect(newcontracts, oldcontracts renter.ContractSet, m *renter.MetaFile, scan renter.ScanFn, height types.BlockHeight) *Operation {
	op := newOperation()
	if len(newcontracts) != len(oldcontracts) {
		op.die(errors.New("new contract set must match size of previous contract set"))
		return op
	}
	migrations := computeMigrations(newcontracts, m.Hosts)
	if len(migrations) == 0 {
		op.die(nil)
		return op
	}
	go migrateDirect(op, newcontracts, oldcontracts, migrations, m, scan, height)
	return op
}

// MigrateDirDirect runs the MigrateDirect process on each meta file in a
// directory.
func MigrateDirDirect(newcontracts renter.ContractSet, nextFile MigrateDirIter, scan renter.ScanFn, height types.BlockHeight) *Operation {
	op := newOperation()
	go migrateDirDirect(op, newcontracts, nextFile, scan, height)
	return op
}

// MigrateRemote uploads file shards to a new set of hosts. The shards are
// retrieved by downloading the file from the current set of hosts. (However,
// MigrateRemote never downloads from hosts that are not in the new set.)
func MigrateRemote(newcontracts, oldcontracts renter.ContractSet, m *renter.MetaFile, scan renter.ScanFn, height types.BlockHeight) *Operation {
	op := newOperation()
	if len(newcontracts) != len(oldcontracts) {
		op.die(errors.New("new contract set must match size of previous contract set"))
		return op
	}
	migrations := computeMigrations(newcontracts, m.Hosts)
	if len(migrations) == 0 {
		op.die(nil)
		return op
	} else if len(m.Hosts)-len(migrations) < m.MinShards {
		op.die(errors.New("not enough existing hosts to recover file"))
		return op
	}
	go migrateRemote(op, newcontracts, oldcontracts, migrations, m, scan, height)
	return op
}

// MigrateDirRemote runs the MigrateRemote process on each meta file in a
// directory.
func MigrateDirRemote(newcontracts renter.ContractSet, nextFile MigrateDirIter, scan renter.ScanFn, height types.BlockHeight) *Operation {
	op := newOperation()
	go migrateDirRemote(op, newcontracts, nextFile, scan, height)
	return op
}

func computeMigrations(contracts renter.ContractSet, hosts []hostdb.HostPublicKey) map[hostdb.HostPublicKey]hostdb.HostPublicKey {
	migrations := make(map[hostdb.HostPublicKey]hostdb.HostPublicKey)
	var newhosts []hostdb.HostPublicKey
outer:
	for host := range contracts {
		for _, h := range hosts {
			if h == host {
				continue outer
			}
		}
		newhosts = append(newhosts, host)
	}

	for _, hostKey := range hosts {
		if _, ok := contracts[hostKey]; !ok {
			migrations[hostKey] = newhosts[0]
			newhosts = newhosts[1:]
		}
	}
	return migrations
}

func migrateFile(op *Operation, f *os.File, newcontracts renter.ContractSet, migrations map[hostdb.HostPublicKey]hostdb.HostPublicKey, m *renter.MetaFile, scan renter.ScanFn, currentHeight types.BlockHeight) {
	hosts := make([]*renter.ShardUploader, len(m.Hosts))
	for i, hostKey := range m.Hosts {
		if op.Canceled() {
			op.die(ErrCanceled)
			return
		}
		newhost, ok := migrations[hostKey]
		if !ok {
			// not migrating this shard
			continue
		}
		contract, ok := newcontracts[newhost]
		if !ok {
			panic("missing contract for host being migrated")
		}
		hu, err := renter.NewShardUploader(m, m.HostIndex(hostKey), contract, scan, currentHeight)
		if err != nil {
			op.die(err)
			return
		}
		defer hu.Close()
		hosts[i] = hu
	}

	// determine size of each chunk
	// NOTE: currently we just use the first shard. This works as long as all
	// shards have the same pattern of slice lengths, but it feels ugly. This
	// is an inherent flaw in the format, and is a good argument for making
	// the format chunk-based instead of host-based.
	var shard []renter.SectorSlice
	for oldhost := range migrations {
		var err error
		shard, err = renter.ReadShard(m.ShardPath(oldhost))
		if err != nil {
			op.die(err)
			return
		}
		if len(shard) > 0 {
			break
		}
	}
	var total, uploaded int64
	chunkSizes := make([]int, len(shard))
	for i, s := range shard {
		chunkSizes[i] = int(s.Length) * m.MinShards
		total += int64(s.Length)
	}
	if total == 0 {
		// nothing to do
		op.die(nil)
		return
	}
	op.sendUpdate(TransferProgressUpdate{
		Total:       total,
		Transferred: uploaded,
	})

	// upload one chunk at a time
	chunk := make([]byte, m.MaxChunkSize()) // no chunk will be larger than this
	rsc := m.ErasureCode()
	for chunkIndex, chunkSize := range chunkSizes {
		if op.Canceled() {
			op.die(ErrCanceled)
			return
		}
		// read chunk
		n, err := io.ReadFull(f, chunk[:chunkSize])
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			op.die(errors.Wrap(err, "could not read file data"))
			return
		} else if n == 0 {
			break
		}

		// encode the chunk, then encrypt and upload each shard
		shards := rsc.Encode(chunk[:n])
		for shardIndex, host := range hosts {
			if host == nil {
				// already uploaded to this host
				continue
			}
			s, err := host.EncryptAndUpload(shards[shardIndex], int64(chunkIndex))
			if err != nil {
				op.die(errors.Wrap(err, "could not upload sector"))
				return
			}
			uploaded += int64(s.Length)
			op.sendUpdate(TransferProgressUpdate{
				Total:       total,
				Transferred: uploaded,
			})
		}
	}

	// finalize new host set
	for oldHostKey, newHostKey := range migrations {
		m.ReplaceHost(oldHostKey, newHostKey)
	}
	op.die(nil)
}

func migrateDirect(op *Operation, newcontracts, oldcontracts renter.ContractSet, migrations map[hostdb.HostPublicKey]hostdb.HostPublicKey, m *renter.MetaFile, scan renter.ScanFn, currentHeight types.BlockHeight) {
	oldhosts := make([]*renter.ShardDownloader, 0, len(migrations))
	newhosts := make([]*renter.ShardUploader, 0, len(migrations))
	for oldHostKey, newHostKey := range migrations {
		if op.Canceled() {
			op.die(ErrCanceled)
			return
		}
		// create downloader for old host
		oldContract, ok := oldcontracts[oldHostKey]
		if !ok {
			panic("oldcontracts does not contain one of the hosts being migrated from")
		}
		bd, err := renter.NewShardDownloader(m, oldContract, scan)
		if err != nil {
			op.sendUpdate(MigrateSkipUpdate{Host: oldHostKey, Err: err})
			continue
		}
		defer bd.Close()

		// create uploader for new host
		newContract, ok := newcontracts[newHostKey]
		if !ok {
			panic("newcontracts does not contain one of the hosts being migrated to")
		}
		hu, err := renter.NewShardUploader(m, m.HostIndex(oldHostKey), newContract, scan, currentHeight)
		if err != nil {
			op.sendUpdate(MigrateSkipUpdate{Host: oldHostKey, Err: err})
			continue
		}
		defer hu.Close()

		oldhosts = append(oldhosts, bd)
		newhosts = append(newhosts, hu)
	}

	var total, uploaded int64
	for _, h := range oldhosts {
		total += int64(len(h.Slices)) * proto.SectorSize
	}
	if total == 0 {
		// nothing to do
		op.die(nil)
		return
	}
	op.sendUpdate(TransferProgressUpdate{
		Total:       total,
		Transferred: uploaded,
	})

	// migrate each old-new pair
	for i := range oldhosts {
		oldHost := oldhosts[i]
		newHost := newhosts[i]
		for chunkIndex, s := range oldHost.Slices {
			if op.Canceled() {
				op.die(ErrCanceled)
				return
			}
			// download a sector
			sector, err := oldHost.Downloader.Sector(s.MerkleRoot)
			if err != nil {
				op.sendUpdate(MigrateSkipUpdate{Host: oldHost.HostKey(), Err: err})
				total -= int64(len(oldHost.Slices[chunkIndex:])) * proto.SectorSize
				break
			}

			// upload the sector to the new host
			if _, err := newHost.Uploader.Upload(sector); err != nil {
				op.sendUpdate(MigrateSkipUpdate{Host: oldHost.HostKey(), Err: err})
				total -= int64(len(oldHost.Slices[chunkIndex:])) * proto.SectorSize
				break
			}
			// write SectorSlice
			if err := newHost.Shard.WriteSlice(s, int64(chunkIndex)); err != nil {
				op.sendUpdate(MigrateSkipUpdate{Host: oldHost.HostKey(), Err: err})
				total -= int64(len(oldHost.Slices[chunkIndex:])) * proto.SectorSize
				break
			}
			uploaded += proto.SectorSize
			op.sendUpdate(TransferProgressUpdate{
				Total:       total,
				Transferred: uploaded,
			})
		}

		m.ReplaceHost(oldHost.HostKey(), newHost.HostKey())
	}

	op.die(nil)
}

func migrateRemote(op *Operation, newcontracts, oldcontracts renter.ContractSet, migrations map[hostdb.HostPublicKey]hostdb.HostPublicKey, m *renter.MetaFile, scan renter.ScanFn, currentHeight types.BlockHeight) {
	// create a downloader for each old host
	oldhosts := make([]*renter.ShardDownloader, len(m.Hosts))
	var errStrings []string
	for i, hostKey := range m.Hosts {
		if op.Canceled() {
			op.die(ErrCanceled)
			return
		}
		// don't download from hosts being migrated from
		if _, ok := migrations[hostKey]; ok {
			errStrings = append(errStrings, fmt.Sprintf("%v: host is being migrated away from", hostKey.ShortKey()))
			continue
		}
		// lookup contract
		contract, ok := oldcontracts[hostKey]
		if !ok {
			errStrings = append(errStrings, fmt.Sprintf("%v: no contract for host", hostKey.ShortKey()))
			continue
		}
		bd, err := renter.NewShardDownloader(m, contract, scan)
		if err != nil {
			errStrings = append(errStrings, err.Error())
			continue
		}
		defer bd.Close()
		oldhosts[i] = bd
	}
	if len(m.Hosts)-len(errStrings) < m.MinShards {
		op.die(errors.New("couldn't connect to enough hosts:\n" + strings.Join(errStrings, "\n")))
		return
	}

	// create an uploader for each new host. Only the indices corresponding to
	// hosts being migrated will be valid.
	newhosts := make([]*renter.ShardUploader, len(m.Hosts))
	for oldHostKey, newHostKey := range migrations {
		if op.Canceled() {
			op.die(ErrCanceled)
			return
		}
		newContract, ok := newcontracts[newHostKey]
		if !ok {
			panic("newcontracts does not contain one of the hosts being migrated to")
		}
		hu, err := renter.NewShardUploader(m, m.HostIndex(oldHostKey), newContract, scan, currentHeight)
		if err != nil {
			op.die(err)
			return
		}
		defer hu.Close()
		newhosts[m.HostIndex(oldHostKey)] = hu
	}

	// determine how many bytes will be uploaded
	// NOTE: currently we just use the first shard and multiply its total
	// length by the number of new hosts. This works as long as all shards have
	// the same pattern of slice lengths, but it feels ugly.
	var total, uploaded, numChunks int64
	for _, h := range oldhosts {
		if len(h.Slices) == 0 {
			continue
		}
		for _, s := range h.Slices {
			total += int64(s.Length) * int64(len(migrations))
		}
		numChunks = int64(len(h.Slices))
		break
	}
	if total == 0 {
		// nothing to do
		op.die(nil)
		return
	}
	op.sendUpdate(TransferProgressUpdate{
		Total:       total,
		Transferred: uploaded,
	})

	// download and reupload each chunk
	rsc := m.ErasureCode()
	for chunkIndex := int64(0); chunkIndex < numChunks; chunkIndex++ {
		if op.Canceled() {
			op.die(ErrCanceled)
			return
		}

		// download chunk shards in parallel and reconstruct
		shards, _, err := DownloadChunkShards(oldhosts, chunkIndex, m.MinShards, op.cancel)
		if err != nil {
			op.die(err)
			return
		} else if err := rsc.Reconstruct(shards); err != nil {
			op.die(err)
			return
		}

		// upload shards to their respective new hosts
		for shardIndex, h := range newhosts {
			if h == nil {
				continue
			}
			s, err := h.EncryptAndUpload(shards[shardIndex], chunkIndex)
			if err != nil {
				op.die(err)
				return
			}
			uploaded += int64(s.Length)
			op.sendUpdate(TransferProgressUpdate{
				Total:       total,
				Transferred: uploaded,
			})
		}
	}

	// finalize new host set
	for oldHostKey, newHostKey := range migrations {
		m.ReplaceHost(oldHostKey, newHostKey)
	}
	op.die(nil)
}

func migrateDirFile(op *Operation, newcontracts renter.ContractSet, nextFile FileIter, scan renter.ScanFn, height types.BlockHeight) {
	for {
		metaPath, filePath, err := nextFile()
		if err == io.EOF {
			break
		} else if err != nil {
			op.sendUpdate(DirSkipUpdate{Filename: metaPath, Err: err})
			continue
		}
		err = func() error {
			index, err := renter.ReadMetaIndex(metaPath)
			if err != nil {
				return err
			}
			// if metafile is already fully migrated, skip it
			migrations := computeMigrations(newcontracts, index.Hosts)
			if len(migrations) == 0 {
				return errors.New("already migrated")
			}
			m, err := renter.ExtractMetaFile(metaPath)
			if err != nil {
				return err
			}
			defer m.Archive(metaPath)

			f, err := os.Open(filePath)
			if err != nil {
				return err
			}
			defer f.Close()

			op.sendUpdate(DirQueueUpdate{Filename: metaPath, Filesize: m.Filesize})
			mop := MigrateFile(f, newcontracts, m, scan, height)
			// cancel mop if op is canceled
			done := make(chan struct{})
			defer close(done)
			go func() {
				select {
				case <-op.cancel:
					mop.Cancel()
				case <-done:
				}
			}()
			// forward mop updates to op
			for u := range mop.Updates() {
				op.sendUpdate(u)
			}
			return mop.Err()
		}()
		if err != nil {
			op.sendUpdate(DirSkipUpdate{Filename: metaPath, Err: err})
		}
	}
	op.die(nil)
}

func migrateDirDirect(op *Operation, newcontracts renter.ContractSet, nextFile MigrateDirIter, scan renter.ScanFn, height types.BlockHeight) {
	for {
		metaPath, oldcontracts, err := nextFile()
		if err == io.EOF {
			break
		} else if err != nil {
			op.sendUpdate(DirSkipUpdate{Filename: metaPath, Err: err})
			continue
		}
		err = func() error {
			defer oldcontracts.Close()
			if len(newcontracts) != len(oldcontracts) {
				return errors.New("new contract set must match size of previous contract set")
			}
			index, err := renter.ReadMetaIndex(metaPath)
			if err != nil {
				return err
			}
			// if metafile is already fully migrated, skip it
			migrations := computeMigrations(newcontracts, index.Hosts)
			if len(migrations) == 0 {
				return errors.New("already migrated")
			}
			m, err := renter.ExtractMetaFile(metaPath)
			if err != nil {
				return err
			}
			defer m.Archive(metaPath)

			op.sendUpdate(DirQueueUpdate{Filename: metaPath, Filesize: m.Filesize})
			mop := MigrateDirect(newcontracts, oldcontracts, m, scan, height)
			// cancel mop if op is canceled
			done := make(chan struct{})
			defer close(done)
			go func() {
				select {
				case <-op.cancel:
					mop.Cancel()
				case <-done:
				}
			}()
			// forward mop updates to op
			for u := range mop.Updates() {
				op.sendUpdate(u)
			}
			return mop.Err()
		}()
		if err != nil {
			op.sendUpdate(DirSkipUpdate{Filename: metaPath, Err: err})
		}
	}
	op.die(nil)
}

func migrateDirRemote(op *Operation, newcontracts renter.ContractSet, nextFile MigrateDirIter, scan renter.ScanFn, height types.BlockHeight) {
	for {
		metaPath, oldcontracts, err := nextFile()
		if err == io.EOF {
			break
		} else if err != nil {
			op.sendUpdate(DirSkipUpdate{Filename: metaPath, Err: err})
			continue
		}
		err = func() error {
			defer oldcontracts.Close()
			if len(newcontracts) != len(oldcontracts) {
				return errors.New("new contract set must match size of previous contract set")
			}
			index, err := renter.ReadMetaIndex(metaPath)
			if err != nil {
				return err
			}
			// if metafile is already fully migrated, skip it
			migrations := computeMigrations(newcontracts, index.Hosts)
			if len(migrations) == 0 {
				return errors.New("already migrated")
			}
			m, err := renter.ExtractMetaFile(metaPath)
			if err != nil {
				return err
			}
			defer m.Archive(metaPath)

			op.sendUpdate(DirQueueUpdate{Filename: metaPath, Filesize: m.Filesize})
			mop := MigrateRemote(newcontracts, oldcontracts, m, scan, height)
			// cancel mop if op is canceled
			done := make(chan struct{})
			defer close(done)
			go func() {
				select {
				case <-op.cancel:
					mop.Cancel()
				case <-done:
				}
			}()
			// forward mop updates to op
			for u := range mop.Updates() {
				op.sendUpdate(u)
			}
			return mop.Err()
		}()
		if err != nil {
			op.sendUpdate(DirSkipUpdate{Filename: metaPath, Err: err})
		}
	}
	op.die(nil)
}

// MigrateDirIter is an iterator that returns the next metafile path and the
// ContractSet containing the metafile's contracts. It should return io.EOF to
// signal the end of iteration.
type MigrateDirIter func() (string, renter.ContractSet, error)

// NewRecursiveMigrateDirIter returns a MigrateDirIter that iterates over a
// nested set of directories.
func NewRecursiveMigrateDirIter(metaDir, contractDir string) MigrateDirIter {
	type walkFile struct {
		name string
		err  error
	}
	fileChan := make(chan walkFile)
	go func() {
		filepath.Walk(metaDir, func(name string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				fileChan <- walkFile{name, err}
			}
			return nil
		})
		close(fileChan)
	}()
	return func() (string, renter.ContractSet, error) {
		wf, ok := <-fileChan
		if !ok {
			return "", nil, io.EOF
		} else if wf.err != nil {
			return wf.name, nil, wf.err
		}
		m, err := renter.ReadMetaIndex(wf.name)
		if err != nil {
			return wf.name, nil, err
		}
		contracts, err := loadMetaContracts(m, contractDir)
		if err != nil {
			return wf.name, nil, err
		}
		return wf.name, contracts, nil
	}
}

func loadMetaContracts(m renter.MetaIndex, dir string) (renter.ContractSet, error) {
	d, err := os.Open(dir)
	if err != nil {
		return nil, errors.Wrap(err, "could not open contract dir")
	}
	defer d.Close()
	filenames, err := d.Readdirnames(-1)
	if err != nil {
		return nil, errors.Wrap(err, "could not read contract dir")
	}

	contracts := make(renter.ContractSet)
	for _, h := range m.Hosts {
		for _, name := range filenames {
			if strings.HasPrefix(name, h.ShortKey()) {
				c, err := renter.LoadContract(filepath.Join(dir, name))
				if err != nil {
					return nil, errors.Wrap(err, "could not read contract")
				}
				contracts[h] = c
			}
		}
	}
	return contracts, nil
}
