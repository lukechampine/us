// Package renter provides formats for contracts and files.
package renter // import "lukechampine.com/us/renter"

import (
	"archive/tar"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"time"
	"unsafe"

	"github.com/aead/chacha20/chacha"
	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/fastrand"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renterhost"
)

const (
	// MetaFileVersion is the current version of the metafile format. It is
	// incremented after each change to the format.
	MetaFileVersion = 2

	// SectorSliceSize is the encoded size of a SectorSlice.
	SectorSliceSize = 64

	indexFilename = "index"
)

// assert that SectorSliceSize is accurate
var _ [SectorSliceSize]struct{} = [unsafe.Sizeof(SectorSlice{})]struct{}{}

// A MetaFile is a set of metadata that represents a file stored on Sia hosts.
type MetaFile struct {
	MetaIndex
	Shards    [][]SectorSlice
	hostIndex map[hostdb.HostPublicKey]int
	filename  string
}

// A MetaIndex contains the traditional file metadata for a MetaFile, along with
// an encryption key, redundancy parameters, and the set of hosts storing the
// actual file data.
type MetaIndex struct {
	Version   int
	Filesize  int64       // original file size
	Mode      os.FileMode // mode bits
	ModTime   time.Time   // set when Archive is called
	MasterKey KeySeed     // seed from which shard encryption keys are derived
	MinShards int         // number of shards required to recover file
	Hosts     []hostdb.HostPublicKey
}

// A SectorSlice uniquely identifies a contiguous slice of data stored on a
// host. Each SectorSlice can only address a single host sector, so multiple
// SectorSlices may be needed to reference the data comprising a file.
type SectorSlice struct {
	MerkleRoot   crypto.Hash
	SegmentIndex uint32
	NumSegments  uint32
	Nonce        [24]byte
}

// A KeySeed derives subkeys and uses them to encrypt and decrypt messages.
type KeySeed [32]byte

// MarshalJSON implements the json.Marshaler interface.
func (s KeySeed) MarshalJSON() ([]byte, error) {
	return []byte(`"` + hex.EncodeToString(s[:]) + `"`), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (s *KeySeed) UnmarshalJSON(b []byte) error {
	if len(b) < 1 {
		return errors.New("wrong seed length")
	}
	if n, err := hex.Decode(s[:], b[1:len(b)-1]); err != nil {
		return err
	} else if n != len(s) {
		return errors.New("wrong seed length")
	}
	return nil
}

// XORKeyStream xors msg with the keystream derived from s, using startIndex as
// the starting offset within the stream. The nonce must be 24 bytes.
func (s *KeySeed) XORKeyStream(msg []byte, nonce []byte, startIndex uint64) {
	if len(msg)%merkle.SegmentSize != 0 {
		panic("message must be a multiple of segment size")
	} else if len(nonce) != chacha.XNonceSize {
		panic("nonce must be 24 bytes")
	}
	// NOTE: since we're using XChaCha20, the nonce and KeySeed are hashed
	// together to produce a subkey; this is why s is referred to as a "seed"
	// rather than a key in its own right.
	c, err := chacha.NewCipher(nonce, s[:], 20)
	if err != nil {
		panic(err)
	}
	c.SetCounter(startIndex)
	c.XORKeyStream(msg, msg)
}

// MaxChunkSize returns the maximum amount of file data that can fit into a
// chunk. A chunk is a buffer of file data pre-erasure coding. When the chunk
// is encoded, it is split into len(m.Hosts) shards of equal size. Thus the
// MaxChunkSize is the size of such a buffer that results in shards equal to
// renterhost.SectorSize. MaxChunkSize is NOT guaranteed to match the actual
// chunk size used in the shard files of m.
func (m *MetaIndex) MaxChunkSize() int64 {
	return renterhost.SectorSize * int64(m.MinShards)
}

// MinChunkSize is the size of the smallest possible chunk. When this chunk is
// erasure-encoded into shards, each shard will have a length of
// merkle.SegmentSize, which is the smallest unit of data that the host can
// provide Merkle proofs for.
func (m *MetaIndex) MinChunkSize() int64 {
	return merkle.SegmentSize * int64(m.MinShards)
}

// ErasureCode returns the erasure code used to encode and decode the shards
// of m.
func (m *MetaIndex) ErasureCode() ErasureCoder {
	return NewRSCode(m.MinShards, len(m.Hosts))
}

// Commit creates a gzipped tar archive containing the metafile's index and
// shards, writes it to filename. The write is atomic.
func (m *MetaFile) Commit(filename string) error {
	f, err := os.Create(filename + "_tmp")
	if err != nil {
		return errors.Wrap(err, "could not create archive")
	}
	defer f.Close()
	zip := gzip.NewWriter(f)
	tw := tar.NewWriter(zip)

	// write index
	index, _ := json.Marshal(m.MetaIndex)
	err = tw.WriteHeader(&tar.Header{
		Name: indexFilename,
		Size: int64(len(index)),
		Mode: 0666,
	})
	if err != nil {
		return errors.Wrap(err, "could not write index header")
	} else if _, err = tw.Write(index); err != nil {
		return errors.Wrap(err, "could not write index")
	}

	// write shards
	encSlice := make([]byte, SectorSliceSize)
	for i, hostKey := range m.Hosts {
		err = tw.WriteHeader(&tar.Header{
			Name: hostKey.Key() + ".shard",
			Size: int64(len(m.Shards[i])) * SectorSliceSize,
			Mode: 0666,
		})
		if err != nil {
			return errors.Wrap(err, "could not write shard header")
		}
		for _, ss := range m.Shards[i] {
			copy(encSlice, ss.MerkleRoot[:])
			binary.LittleEndian.PutUint32(encSlice[32:], ss.SegmentIndex)
			binary.LittleEndian.PutUint32(encSlice[36:], ss.NumSegments)
			copy(encSlice[40:], ss.Nonce[:])
			if _, err = tw.Write(encSlice); err != nil {
				return errors.Wrap(err, "could not add shard to archive")
			}
		}
	}

	// flush, close, and atomically rename
	if err := tw.Close(); err != nil {
		return errors.Wrap(err, "could not write tar data")
	} else if err := zip.Close(); err != nil {
		return errors.Wrap(err, "could not write gzip data")
	} else if err := f.Sync(); err != nil {
		return errors.Wrap(err, "could not sync archive file")
	} else if err := f.Close(); err != nil {
		return errors.Wrap(err, "could not close archive file")
	} else if err := os.Rename(filename+"_tmp", filename); err != nil {
		return errors.Wrap(err, "could not atomically replace archive file")
	}

	return nil
}

// Close commits the MetaFile to disk, using the same filename passed to
// NewMetaFile or ReadMetaFile.
func (m *MetaFile) Close() error {
	// TODO: may make sense to drop Close entirely, since it can be misleading;
	// e.g. if you just want to read a metafile without changing it, Close
	// results in needless I/O.
	return m.Commit(m.filename)
}

// HostIndex returns the index of the shard that references data stored on the
// specified host. If m does not reference any data on the host, HostIndex
// returns -1.
func (m *MetaFile) HostIndex(hostKey hostdb.HostPublicKey) int {
	i, ok := m.hostIndex[hostKey]
	if !ok {
		i = -1
	}
	return i
}

// ReplaceHost replaces a host within the metafile. The shards of the replaced
// host will not be included in the new archive when Close or Archive is called.
func (m *MetaFile) ReplaceHost(oldHostKey, newHostKey hostdb.HostPublicKey) bool {
	for i, h := range m.Hosts {
		if h == oldHostKey {
			m.Hosts[i] = newHostKey
			return true
		}
	}
	return false
}

// NewMetaFile creates a metafile using the specified hosts and erasure-
// coding parameters.
func NewMetaFile(filename string, mode os.FileMode, size int64, hosts []hostdb.HostPublicKey, minShards int) *MetaFile {
	if minShards > len(hosts) {
		panic("minShards cannot be greater than the number of hosts")
	}
	hostIndex := make(map[hostdb.HostPublicKey]int)
	for i, hostKey := range hosts {
		hostIndex[hostKey] = i
	}
	m := &MetaFile{
		MetaIndex: MetaIndex{
			Version:   MetaFileVersion,
			Filesize:  size,
			Mode:      mode,
			ModTime:   time.Now(),
			MinShards: minShards,
			Hosts:     hosts,
		},
		Shards:    make([][]SectorSlice, len(hosts)),
		hostIndex: hostIndex,
		filename:  filename,
	}
	fastrand.Read(m.MasterKey[:])
	return m
}

// ReadMetaFile reads a metafile archive into memory.
func ReadMetaFile(filename string) (*MetaFile, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, errors.Wrap(err, "could not open archive")
	}
	defer f.Close()
	zip, err := gzip.NewReader(f)
	if err != nil {
		return nil, errors.Wrap(err, "could not read gzip header")
	}
	tr := tar.NewReader(zip)

	m := &MetaFile{
		hostIndex: make(map[hostdb.HostPublicKey]int),
		filename:  filename,
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			if m.Version == 0 {
				return nil, errors.New("archive is missing an index")
			}
			break
		} else if err != nil {
			return nil, errors.Wrap(err, "could not read archive entry")
		}

		if hdr.Name == indexFilename {
			// read index
			if err = json.NewDecoder(tr).Decode(&m.MetaIndex); err != nil {
				return nil, errors.Wrap(err, "could not decode index")
			}
			for i, h := range m.MetaIndex.Hosts {
				m.hostIndex[h] = i
			}
		} else {
			// read shard
			shard := make([]SectorSlice, hdr.Size/SectorSliceSize)
			buf := make([]byte, SectorSliceSize)
			for i := range shard {
				if _, err := io.ReadFull(tr, buf); err != nil {
					return nil, errors.Wrap(err, "could not read shard")
				}
				copy(shard[i].MerkleRoot[:], buf[:32])
				shard[i].SegmentIndex = binary.LittleEndian.Uint32(buf[32:36])
				shard[i].NumSegments = binary.LittleEndian.Uint32(buf[36:40])
				copy(shard[i].Nonce[:], buf[40:64])
			}
			m.Shards = append(m.Shards, shard)
		}
	}

	if err := zip.Close(); err != nil {
		return nil, errors.Wrap(err, "archive is corrupted")
	}
	return m, nil
}

// ReadMetaIndex reads the index of a metafile without reading any shards.
func ReadMetaIndex(filename string) (MetaIndex, error) {
	f, err := os.Open(filename)
	if err != nil {
		return MetaIndex{}, errors.Wrap(err, "could not open archive")
	}
	defer f.Close()

	zip, err := gzip.NewReader(f)
	if err != nil {
		return MetaIndex{}, errors.Wrap(err, "could not read gzip header")
	}
	defer zip.Close()

	var index MetaIndex
	tr := tar.NewReader(zip)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return MetaIndex{}, errors.Wrap(err, "could not read archive entry")
		} else if hdr.Name != indexFilename {
			continue // skip entry
		}

		if err := json.NewDecoder(tr).Decode(&index); err != nil {
			return MetaIndex{}, errors.Wrap(err, "could not decode index")
		}
		// done
		return index, nil
	}
	return MetaIndex{}, errors.New("archive is missing an index")
}

// MetaFileFullyUploaded reads a metafile archive and reports whether it has
// been fully uploaded.
func MetaFileFullyUploaded(filename string) (bool, error) {
	index, shards, err := readMetaFileShards(filename)
	if err != nil {
		return false, err
	}
	return shards == len(index.Hosts), nil
}

// MetaFileCanDownload reads a metafile archive and reports whether it can be
// downloaded.
func MetaFileCanDownload(filename string) (bool, error) {
	index, shards, err := readMetaFileShards(filename)
	if err != nil {
		return false, err
	}
	return shards >= index.MinShards, nil
}

// readMetaFileShards reads a metafile and returns its index and the number of
// shards that represent fully-uploaded shards of the erasure-encoded file.
func readMetaFileShards(filename string) (MetaIndex, int, error) {
	f, err := os.Open(filename)
	if err != nil {
		return MetaIndex{}, 0, errors.Wrap(err, "could not open archive")
	}
	defer f.Close()

	zip, err := gzip.NewReader(f)
	if err != nil {
		return MetaIndex{}, 0, errors.Wrap(err, "could not read gzip header")
	}
	defer zip.Close()

	var index MetaIndex
	var shardSizes []int64
	tr := tar.NewReader(zip)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return MetaIndex{}, 0, errors.Wrap(err, "could not read archive entry")
		}
		if hdr.Name == "index" {
			if err := json.NewDecoder(tr).Decode(&index); err != nil {
				return MetaIndex{}, 0, errors.Wrap(err, "could not decode index")
			}
		} else {
			// read shard contents, adding each length value
			numSlices := int(hdr.FileInfo().Size() / SectorSliceSize)
			var numSegments int64
			buf := make([]byte, SectorSliceSize)
			for i := 0; i < numSlices; i++ {
				if _, err := io.ReadFull(tr, buf); err != nil {
					return MetaIndex{}, 0, errors.Wrap(err, "could not read shard")
				}
				numSegments += int64(binary.LittleEndian.Uint32(buf[36:40]))
			}
			shardSizes = append(shardSizes, numSegments*merkle.SegmentSize)
		}
	}

	// count full shards
	fullShardSize := index.Filesize / int64(index.MinShards)
	var fullShards int
	for _, bs := range shardSizes {
		if bs >= fullShardSize {
			fullShards++
		}
	}
	return index, fullShards, nil
}
