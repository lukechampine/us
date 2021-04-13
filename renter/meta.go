// Package renter provides utilities for managing Sia file metadata and for
// uploading and downloading sectors.
package renter // import "lukechampine.com/us/renter"

import (
	"archive/tar"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/aead/chacha20/chacha"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"lukechampine.com/frand"
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
	Shards [][]SectorSlice
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

// RandomNonce returns a random nonce, suitable for encrypting sector data.
func RandomNonce() [24]byte {
	return frand.Entropy192()
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

// Validate performs basic sanity checks on a MetaIndex.
func (m *MetaIndex) Validate() error {
	switch {
	case m.Version != MetaFileVersion:
		return fmt.Errorf("incompatible version (%v, want %v)", m.Version, MetaFileVersion)
	case m.MinShards == 0:
		return fmt.Errorf("MinShards cannot be 0")
	case m.MinShards > len(m.Hosts):
		return fmt.Errorf("MinShards (%v) must not exceed number of hosts (%v)", m.Version, len(m.Hosts))
	}
	return nil
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

// HostIndex returns the index of the shard that references data stored on the
// specified host. If m does not reference any data on the host, HostIndex
// returns -1.
func (m *MetaFile) HostIndex(hostKey hostdb.HostPublicKey) int {
	for i, hpk := range m.Hosts {
		if hpk == hostKey {
			return i
		}
	}
	return -1
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
func NewMetaFile(mode os.FileMode, size int64, hosts []hostdb.HostPublicKey, minShards int) *MetaFile {
	if minShards > len(hosts) {
		panic("minShards cannot be greater than the number of hosts")
	}
	return &MetaFile{
		MetaIndex: MetaIndex{
			Version:   MetaFileVersion,
			Filesize:  size,
			Mode:      mode,
			ModTime:   time.Now(),
			MasterKey: frand.Entropy256(),
			MinShards: minShards,
			Hosts:     append([]hostdb.HostPublicKey(nil), hosts...),
		},
		Shards: make([][]SectorSlice, len(hosts)),
	}
}

// WriteMetaFile creates a gzipped tar archive containing m's index and shards,
// and writes it to filename. The write is atomic.
func WriteMetaFile(filename string, m *MetaFile) error {
	// validate before writing
	if err := validateShards(m.Shards); err != nil {
		return fmt.Errorf("invalid shards: %w", err)
	}

	f, err := os.Create(filename + "_tmp")
	if err != nil {
		return fmt.Errorf("could not create archive: %w", err)
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
		return fmt.Errorf("could not write index header: %w", err)
	} else if _, err = tw.Write(index); err != nil {
		return fmt.Errorf("could not write index: %w", err)
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
			return fmt.Errorf("could not write shard header: %w", err)
		}
		for _, ss := range m.Shards[i] {
			copy(encSlice, ss.MerkleRoot[:])
			binary.LittleEndian.PutUint32(encSlice[32:], ss.SegmentIndex)
			binary.LittleEndian.PutUint32(encSlice[36:], ss.NumSegments)
			copy(encSlice[40:], ss.Nonce[:])
			if _, err = tw.Write(encSlice); err != nil {
				return fmt.Errorf("could not add shard to archive: %w", err)
			}
		}
	}

	// flush, close, and atomically rename
	if err := tw.Close(); err != nil {
		return fmt.Errorf("could not write tar data: %w", err)
	} else if err := zip.Close(); err != nil {
		return fmt.Errorf("could not write gzip data: %w", err)
	} else if err := f.Sync(); err != nil {
		return fmt.Errorf("could not sync archive file: %w", err)
	} else if err := f.Close(); err != nil {
		return fmt.Errorf("could not close archive file: %w", err)
	} else if err := os.Rename(filename+"_tmp", filename); err != nil {
		return fmt.Errorf("could not atomically replace archive file: %w", err)
	}

	return nil
}

// ReadMetaFile reads a metafile archive into memory.
func ReadMetaFile(filename string) (*MetaFile, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open archive: %w", err)
	}
	defer f.Close()
	zip, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("could not read gzip header: %w", err)
	}
	tr := tar.NewReader(zip)

	m := &MetaFile{}
	shards := make(map[hostdb.HostPublicKey][]SectorSlice)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			if m.Version == 0 {
				return nil, errors.New("archive is missing an index")
			}
			break
		} else if err != nil {
			return nil, fmt.Errorf("could not read archive entry: %w", err)
		}

		if hdr.Name == indexFilename {
			// read index
			if err = json.NewDecoder(tr).Decode(&m.MetaIndex); err != nil {
				return nil, fmt.Errorf("could not decode index: %w", err)
			}
		} else {
			// read shard
			shard := make([]SectorSlice, hdr.Size/SectorSliceSize)
			buf := make([]byte, SectorSliceSize)
			for i := range shard {
				if _, err := io.ReadFull(tr, buf); err != nil {
					return nil, fmt.Errorf("could not read shard: %w", err)
				}
				copy(shard[i].MerkleRoot[:], buf[:32])
				shard[i].SegmentIndex = binary.LittleEndian.Uint32(buf[32:36])
				shard[i].NumSegments = binary.LittleEndian.Uint32(buf[36:40])
				copy(shard[i].Nonce[:], buf[40:64])
			}
			// shard files can be in any order within the archive, so use name
			// to determine index
			hpk := hostdb.HostPublicKey("ed25519:" + strings.TrimSuffix(hdr.Name, ".shard"))
			shards[hpk] = shard
		}
	}
	if err := zip.Close(); err != nil {
		return nil, fmt.Errorf("archive is corrupted: %w", err)
	}

	// now that we have the index and all shards in memory, order the shards
	// according the Hosts list in the index
	if len(shards) != len(m.Hosts) {
		return nil, fmt.Errorf("invalid metafile: number of shards (%v) does not match number of hosts (%v)", len(shards), len(m.Hosts))
	}
	m.Shards = make([][]SectorSlice, len(m.Hosts))
	for hpk, shard := range shards {
		i := m.HostIndex(hpk)
		if i == -1 {
			return nil, fmt.Errorf("invalid shard filename: host %q not present in index", hpk)
		}
		m.Shards[i] = shard
	}

	if err := validateShards(m.Shards); err != nil {
		return nil, fmt.Errorf("invalid shards: %w", err)
	}

	return m, nil
}

// ReadMetaIndex reads the index of a metafile without reading any shards.
func ReadMetaIndex(filename string) (MetaIndex, error) {
	f, err := os.Open(filename)
	if err != nil {
		return MetaIndex{}, fmt.Errorf("could not open archive: %w", err)
	}
	defer f.Close()

	zip, err := gzip.NewReader(f)
	if err != nil {
		return MetaIndex{}, fmt.Errorf("could not read gzip header: %w", err)
	}
	defer zip.Close()

	var index MetaIndex
	tr := tar.NewReader(zip)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return MetaIndex{}, fmt.Errorf("could not read archive entry: %w", err)
		} else if hdr.Name != indexFilename {
			continue // skip entry
		}

		if err := json.NewDecoder(tr).Decode(&index); err != nil {
			return MetaIndex{}, fmt.Errorf("could not decode index: %w", err)
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
		return MetaIndex{}, 0, fmt.Errorf("could not open archive: %w", err)
	}
	defer f.Close()

	zip, err := gzip.NewReader(f)
	if err != nil {
		return MetaIndex{}, 0, fmt.Errorf("could not read gzip header: %w", err)
	}
	defer zip.Close()

	var haveIndex bool
	var index MetaIndex
	var shardSizes []int64
	tr := tar.NewReader(zip)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return MetaIndex{}, 0, fmt.Errorf("could not read archive entry: %w", err)
		}
		if hdr.Name == indexFilename {
			if err := json.NewDecoder(tr).Decode(&index); err != nil {
				return MetaIndex{}, 0, fmt.Errorf("could not decode index: %w", err)
			}
			haveIndex = true
		} else {
			// read shard contents, adding each length value
			numSlices := int(hdr.FileInfo().Size() / SectorSliceSize)
			var numSegments int64
			buf := make([]byte, SectorSliceSize)
			for i := 0; i < numSlices; i++ {
				if _, err := io.ReadFull(tr, buf); err != nil {
					return MetaIndex{}, 0, fmt.Errorf("could not read shard: %w", err)
				}
				numSegments += int64(binary.LittleEndian.Uint32(buf[36:40]))
			}
			shardSizes = append(shardSizes, numSegments*merkle.SegmentSize)
		}
	}
	if !haveIndex {
		return MetaIndex{}, 0, errors.New("archive does not contain an index")
	}
	if err := index.Validate(); err != nil {
		return MetaIndex{}, 0, fmt.Errorf("invalid index: %w", err)
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

// validateShards checks that a set of shards does not contain any inconsistent
// chunks.
func validateShards(shards [][]SectorSlice) error {
	if len(shards) < 2 {
		return nil
	}
	for chunkIndex, s := range shards[0] {
		for j := 1; j < len(shards); j++ {
			s2 := shards[j][chunkIndex]
			if s.NumSegments != s2.NumSegments {
				return fmt.Errorf("shards %v and %v differ at chunk %v", 0, j, chunkIndex)
			}
		}
	}
	return nil
}
