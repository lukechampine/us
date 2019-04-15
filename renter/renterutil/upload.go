package renterutil

import (
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/renter"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renterhost"
)

// UploadDir uploads files in a directory, producing a set of metafiles whose
// structure mirrors the original directory. Data from multiple files may be
// packed into a single sector. This greatly improves efficiency when
// uploading many small files.
func UploadDir(nextFile FileIter, contracts renter.ContractSet, minShards int, hkr renter.HostKeyResolver, currentHeight types.BlockHeight) *Operation {
	op := newOperation()
	go uploadDir(op, nextFile, contracts, minShards, hkr, currentHeight)
	return op
}

func uploadDir(op *Operation, nextFile FileIter, contracts renter.ContractSet, minShards int, hkr renter.HostKeyResolver, currentHeight types.BlockHeight) {
	rsc := renter.NewRSCode(minShards, len(contracts))

	// connect to hosts
	var hosts []*proto.Session
	for hostKey, contract := range contracts {
		if op.Canceled() {
			op.die(ErrCanceled)
			return
		}
		hostIP, err := hkr.ResolveHostKey(contract.HostKey())
		if err != nil {
			op.die(errors.Wrapf(err, "%v: could not resolve host key", hostKey.ShortKey()))
			return
		}
		u, err := proto.NewSession(hostIP, contract, currentHeight)
		if err != nil {
			op.die(errors.Wrapf(err, "could not initiate upload to %v", hostKey.ShortKey()))
			return
		}
		defer u.Close()
		// send dial stats
		op.sendUpdate(DialStatsUpdate{
			Host:  u.HostKey(),
			Stats: u.DialStats(),
		})
		hosts = append(hosts, u)
	}

	// This code is tricky.
	//
	// For each file, we need to keep track of its underlying os.File, its
	// associated renter.MetaFile, and its chunk index. And for each chunk, we
	// need to track the offset+length of that chunk's data within the sector
	// uploaded to the host. (The offset+length will be the same for each
	// sector.) This information is all contained in the fileEntry type.
	//
	// We iterate through the set of files with the nextFile function. We read
	// chunk data from each file into a "chunk" byte slice that will be split
	// into host sector data. Once the slice is full or the file has been
	// fully read, we stop and erasure-encode the result. The resulting shards
	// are appended to the sectors destined for each host, and mark the
	// offset+length of the file data within each shard. If the file has been
	// fully read and the chunk is not full, we call nextFile to update the
	// "current file" and repeat the process until the slice is full or all
	// files have been read. Each file whose data is read into the slice is
	// added to a slice of fileSectors.
	//
	// As an optimization, we should avoid adding a file to the chunk slice if:
	//
	//    a) it is too large to fit in the remaining space, AND
	//    b) it is small enough to fit in a single sector.
	//
	// The reason for this is that we would like to avoid requesting two
	// different sectors from a host if one would suffice. The downside of
	// this optimization is that it results in wasted space. The theoretical
	// worst-case scenario is a set of files with alternating sizes of 1 byte
	// and renterhost.SectorSize bytes. If the optimization is applied
	// naively, this results in about a 2x storage blowup. However, this
	// scenario is unlikely to occur in a typical setting; the expected amount
	// of space wasted is about the average size of the files being uploaded
	// that are smaller than one sector. By tweaking the cutoff for applying
	// this optimization (e.g. from SectorSize to SectorSize/4), we can reduce
	// the amount of waste at the cost of requiring two sectors for more
	// files.
	//
	// Once the chunk has been erasure-coded into sectors and each file in
	// each sector has been separately encrypted, the data is ready for
	// upload. The sectors are passed to the shardUploader object, which
	// transfers them to the host, revises the file contract, and calculates
	// the sector's Merkle root. Finally, this root is combined with each
	// file's offset+length metadata to form SectorSlices, which are written to
	// their corresponding Shards.

	type fileEntry struct {
		f           *os.File
		m           *renter.MetaFile
		Close       func() error
		chunkIndex  int64
		totalChunks int64
	}
	nextEntry := func() (fileEntry, error) {
	retry:
		filePath, metaPath, err := nextFile()
		if err != nil {
			return fileEntry{}, err
		}
		f, err := os.Open(filePath)
		if err != nil {
			return fileEntry{}, err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return fileEntry{}, err
		}
		// if metafile already exists and is fully uploaded, skip it
		if done, err := renter.MetaFileFullyUploaded(metaPath); err == nil && done {
			op.sendUpdate(DirSkipUpdate{Filename: filePath, Err: errors.New("already uploaded")})
			f.Close()
			goto retry
		}
		if err := os.MkdirAll(filepath.Dir(metaPath), 0700); err != nil {
			f.Close()
			return fileEntry{}, err
		}
		m, err := renter.NewMetaFile(metaPath, info.Mode(), info.Size(), contracts, minShards)
		if err != nil {
			f.Close()
			return fileEntry{}, err
		}
		if m.Filesize == 0 {
			f.Close()
			m.Close()
			goto retry
		}
		return fileEntry{
			f: f,
			m: m,
			Close: func() error {
				f.Close()
				return m.Close()
			},
			totalChunks: m.MinChunks(),
		}, nil
	}

	curEntry, err := nextEntry()
	if err == io.EOF {
		op.die(nil)
		return
	} else if err != nil {
		op.die(err)
		return
	}
	chunk := make([]byte, curEntry.m.MaxChunkSize())
	sectors := make([]renter.SectorBuilder, len(hosts))
	shards := make([][]byte, len(hosts))
	for i := range shards {
		shards[i] = make([]byte, renterhost.SectorSize)
	}
	for curEntry.f != nil {
		var files []fileEntry

		// reset the sector builders
		for i := range sectors {
			sectors[i].Reset()
		}
		for sectors[0].Len() < renterhost.SectorSize {
			chunk = chunk[:sectors[0].Remaining()*minShards]
			n, err := io.ReadFull(curEntry.f, chunk)
			if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				op.die(errors.Wrap(err, "could not read input stream"))
				return
			} else if n == 0 {
				curEntry, err = nextEntry()
				if err == io.EOF {
					// no more files to process
					break
				} else if err != nil {
					op.die(err)
					return
				}
				// If the sectors are already partially full, adding curEntry
				// to them may increase the total number of chunks required to
				// store curEntry, which increases download latency. We can
				// avoid this by breaking early and starting curEntry at the
				// next chunk. However, this wastes space in the sectors. So
				// we only apply the optimization if the amount of wasted
				// space is acceptable.
				if (curEntry.m.Filesize % curEntry.m.MaxChunkSize()) > int64(len(chunk)) {
					if int64(len(chunk)) < curEntry.m.MaxChunkSize()/4 {
						break
					} else {
						curEntry.totalChunks++
					}
				}
				continue
			}
			chunk = chunk[:n]

			// split the chunk into shards
			rsc.Encode(chunk, shards)

			// append each shard to its corresponding sector
			for i := range sectors {
				hostIndex := curEntry.m.HostIndex(hosts[i].HostKey())
				shard := shards[hostIndex]
				sectors[i].Append(shard, curEntry.m.MasterKey)
			}
			curEntry.chunkIndex++
			files = append(files, curEntry)

			op.sendUpdate(DirQueueUpdate{
				Filename: curEntry.f.Name(),
				Filesize: curEntry.m.Filesize,
			})
		}

		// last check for cancel signal before we start uploading
		if op.Canceled() {
			for _, f := range files {
				if err := f.Close(); err != nil {
					op.die(err)
					return
				}
				f.Close = func() error { return nil }
			}
			if curEntry.Close != nil {
				curEntry.Close()
			}
			op.die(ErrCanceled)
			return
		}

		// upload each sector
		errs := make([]error, len(sectors))
		var wg sync.WaitGroup
		for i := range sectors {
			wg.Add(1)
			go func(shardIndex int) {
				defer wg.Done()
				errs[shardIndex] = func() error {
					// upload shard to host
					host := hosts[shardIndex]
					sb := sectors[shardIndex]
					err := host.Write([]renterhost.RPCWriteAction{{
						Type: renterhost.RPCWriteActionAppend,
						Data: sb.Finish()[:],
					}})
					if err != nil {
						return errors.Wrap(err, "could not upload sector")
					}
					op.sendUpdate(UploadStatsUpdate{
						Host:  host.HostKey(),
						Stats: host.LastUploadStats(),
					})
					slices := sb.Slices()
					// append slices to shards
					//
					// NOTE: no synchronization needed; each goroutine writes
					// to a different file
					//
					// TODO: this code assumes len(slices) == len(files), which
					// is brittle; in the general case, len(slices) >= len(files).
					for i, f := range files {
						if sf, err := renter.OpenShard(f.m.ShardPath(host.HostKey())); err != nil {
							return err
						} else if err := sf.WriteSlice(slices[i], f.chunkIndex-1); err != nil {
							sf.Close()
							return err
						} else if err := sf.Close(); err != nil {
							return err
						}
					}
					return nil
				}()
			}(i)
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				op.die(err)
				return
			}
		}
		// TODO: we have to send all updates at once because otherwise the
		// transfer speed math gets messed up. Maybe put elapsed time in the
		// update, or make caller aware that each update is part of one chunk.
		op.sendUpdate(TransferProgressUpdate{
			Total:       renterhost.SectorSize * int64(len(hosts)) * files[0].totalChunks,
			Transferred: renterhost.SectorSize * int64(len(hosts)) * files[0].chunkIndex,
		})
		for _, f := range files {
			if f.chunkIndex >= f.totalChunks {
				if err := f.Close(); err != nil {
					op.die(err)
					return
				}
			}
		}
	}
	op.die(nil)
}
