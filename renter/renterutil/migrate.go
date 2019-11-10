package renterutil

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renterhost"
)

// newMigrationShardUploader is like renter.NewShardUploader, but uses the old
// host's Shard. This is useful for migration, since the new host won't be in
// the MetaFile yet.
func newMigrationShardUploader(m *renter.MetaFile, c renter.Contract, oldHostKey hostdb.HostPublicKey, hkr renter.HostKeyResolver, currentHeight types.BlockHeight) (*renter.ShardUploader, error) {
	hostKey := c.HostKey
	// get host IP
	hostIP, err := hkr.ResolveHostKey(c.HostKey)
	if err != nil {
		return nil, errors.Wrapf(err, "%v: could not resolve host key", hostKey.ShortKey())
	}
	// create uploader
	u, err := proto.NewSession(hostIP, c.HostKey, c.ID, c.Key, currentHeight)
	if err != nil {
		return nil, errors.Wrapf(err, "%v: could not initiate upload protocol with host", hostKey.ShortKey())
	}
	return &renter.ShardUploader{
		Uploader: u,
		Shard:    &m.Shards[m.HostIndex(oldHostKey)],
		Key:      m.MasterKey,
	}, nil
}

// MigrateFile uploads file shards to a new set of hosts. The shards are
// retrieved by erasure-encoding f.
func MigrateFile(f *os.File, newcontracts renter.ContractSet, m *renter.MetaFile, hkr renter.HostKeyResolver, height types.BlockHeight) *Operation {
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
	go migrateFile(op, f, newcontracts, migrations, m, hkr, height)
	return op
}

// MigrateDirFile runs the MigrateFile process on each metafile in a
// directory, using it's corresponding file on disk. The directory structure
// of the files and metafiles must match.
func MigrateDirFile(newcontracts renter.ContractSet, nextFile FileIter, hkr renter.HostKeyResolver, height types.BlockHeight) *Operation {
	op := newOperation()
	go migrateDirFile(op, newcontracts, nextFile, hkr, height)
	return op
}

// MigrateRemote uploads file shards to a new set of hosts. The shards are
// retrieved by downloading the file from the current set of hosts. (However,
// MigrateRemote never downloads from hosts that are not in the new set.)
func MigrateRemote(newcontracts renter.ContractSet, m *renter.MetaFile, hkr renter.HostKeyResolver, height types.BlockHeight) *Operation {
	op := newOperation()
	migrations := computeMigrations(newcontracts, m.Hosts)
	if len(migrations) == 0 {
		op.die(nil)
		return op
	} else if len(m.Hosts)-len(migrations) < m.MinShards {
		op.die(errors.New("not enough existing hosts to recover file"))
		return op
	}
	go migrateRemote(op, newcontracts, migrations, m, hkr, height)
	return op
}

// MigrateDirRemote runs the MigrateRemote process on each metafile in a
// directory.
func MigrateDirRemote(newcontracts renter.ContractSet, nextFile MigrateDirIter, hkr renter.HostKeyResolver, height types.BlockHeight) *Operation {
	op := newOperation()
	go migrateDirRemote(op, newcontracts, nextFile, hkr, height)
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

func migrateFile(op *Operation, f *os.File, newcontracts renter.ContractSet, migrations map[hostdb.HostPublicKey]hostdb.HostPublicKey, m *renter.MetaFile, hkr renter.HostKeyResolver, currentHeight types.BlockHeight) {
	hosts := make([]*renter.ShardUploader, len(m.Hosts))
	for i, oldHostKey := range m.Hosts {
		if op.Canceled() {
			op.die(ErrCanceled)
			return
		}
		newhost, ok := migrations[oldHostKey]
		if !ok {
			// not migrating this shard
			continue
		}
		contract, ok := newcontracts[newhost]
		if !ok {
			panic("missing contract for host being migrated")
		}
		hu, err := newMigrationShardUploader(m, contract, oldHostKey, hkr, currentHeight)
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
	shard := m.Shards[0]
	if len(shard) == 0 {
		// nothing to do
		op.die(nil)
		return
	}

	// for each host we're migrating to, we need to upload a full sector for
	// each SectorSlice in the file.
	total := int64(len(migrations)*len(shard)) * renterhost.SectorSize
	uploaded := int64(0)
	op.sendUpdate(TransferProgressUpdate{
		Total:       total,
		Transferred: uploaded,
	})

	// upload one chunk at a time
	//
	// NOTE: technically, we should be checking for multiple SectorSlices with
	// the same MerkleRoot, and upload those together in order to save
	// bandwidth.
	chunkSizes := make([]int, len(shard))
	for i, s := range shard {
		chunkSizes[i] = int(s.NumSegments*merkle.SegmentSize) * m.MinShards
	}
	rsc := m.ErasureCode()
	chunk := make([]byte, m.MaxChunkSize()) // no chunk will be larger than this
	shards := make([][]byte, len(hosts))
	for i := range shards {
		shards[i] = make([]byte, renterhost.SectorSize)
	}
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
		rsc.Encode(chunk[:n], shards)
		for shardIndex, host := range hosts {
			if host == nil {
				// already uploaded to this host
				continue
			}
			_, err := host.EncryptAndUpload(shards[shardIndex], int64(chunkIndex))
			if err != nil {
				op.die(errors.Wrap(err, "could not upload sector"))
				return
			}
			uploaded += renterhost.SectorSize
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

func migrateRemote(op *Operation, newcontracts renter.ContractSet, migrations map[hostdb.HostPublicKey]hostdb.HostPublicKey, m *renter.MetaFile, hkr renter.HostKeyResolver, currentHeight types.BlockHeight) {
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
		contract, ok := newcontracts[hostKey]
		if !ok {
			errStrings = append(errStrings, fmt.Sprintf("%v: no contract for host", hostKey.ShortKey()))
			continue
		}
		bd, err := renter.NewShardDownloader(m, contract, hkr)
		if err != nil {
			errStrings = append(errStrings, err.Error())
			continue
		}
		defer bd.Close()
		oldhosts[i] = bd
	}
	if len(m.Hosts)-len(errStrings) < m.MinShards {
		op.die(errors.New("could not connect to enough hosts:\n" + strings.Join(errStrings, "\n")))
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
		hu, err := newMigrationShardUploader(m, newContract, oldHostKey, hkr, currentHeight)
		if err != nil {
			op.die(err)
			return
		}
		defer hu.Close()
		newhosts[m.HostIndex(oldHostKey)] = hu
	}

	// determine how many bytes will be uploaded
	var numChunks int64
	for _, h := range oldhosts {
		if h == nil {
			continue
		}
		numChunks = int64(len(h.Slices))
		break
	}
	if numChunks == 0 {
		// nothing to do
		op.die(nil)
		return
	}

	// for each host we're migrating to, we need to upload a full sector for
	// each SectorSlice in the file.
	total := int64(len(migrations)) * numChunks * renterhost.SectorSize
	uploaded := int64(0)
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
			_, err := h.EncryptAndUpload(shards[shardIndex], chunkIndex)
			if err != nil {
				op.die(err)
				return
			}
			uploaded += renterhost.SectorSize
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

func migrateDirFile(op *Operation, newcontracts renter.ContractSet, nextFile FileIter, hkr renter.HostKeyResolver, height types.BlockHeight) {
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
			m, err := renter.ReadMetaFile(metaPath)
			if err != nil {
				return err
			}
			defer renter.WriteMetaFile(metaPath, m)

			f, err := os.Open(filePath)
			if err != nil {
				return err
			}
			defer f.Close()

			op.sendUpdate(DirQueueUpdate{Filename: metaPath, Filesize: m.Filesize})
			mop := MigrateFile(f, newcontracts, m, hkr, height)
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

func migrateDirRemote(op *Operation, newcontracts renter.ContractSet, nextFile MigrateDirIter, hkr renter.HostKeyResolver, height types.BlockHeight) {
	for {
		metaPath, err := nextFile()
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
			m, err := renter.ReadMetaFile(metaPath)
			if err != nil {
				return err
			}
			defer renter.WriteMetaFile(metaPath, m)

			op.sendUpdate(DirQueueUpdate{Filename: metaPath, Filesize: m.Filesize})
			mop := MigrateRemote(newcontracts, m, hkr, height)
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

// MigrateDirIter is an iterator that returns the next metafile path. It should
// return io.EOF to signal the end of iteration.
type MigrateDirIter func() (string, error)

// NewRecursiveMigrateDirIter returns a MigrateDirIter that iterates over a
// nested set of directories.
func NewRecursiveMigrateDirIter(metaDir string) MigrateDirIter {
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
	return func() (string, error) {
		wf, ok := <-fileChan
		if !ok {
			return "", io.EOF
		} else if wf.err != nil {
			return wf.name, wf.err
		}
		return wf.name, nil
	}
}
