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
	"path/filepath"
	"time"

	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter/proto"

	"github.com/aead/chacha20/chacha"
	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/fastrand"
	"golang.org/x/crypto/blake2b"
)

const (
	// MetaFileVersion is the current version of the meta file format. It is
	// incremented after each change to the format.
	MetaFileVersion = 1

	indexFilename = "index"
)

// A MetaFile represents an extracted meta file archive.
type MetaFile struct {
	MetaIndex
	hostIndex map[hostdb.HostPublicKey]int
	Workdir   string
}

// A MetaIndex contains the metadata that ties shards together into a single
// object with file semantics.
type MetaIndex struct {
	Version   int
	Filesize  int64       // original file size
	Mode      os.FileMode // mode bits
	ModTime   time.Time   // set when Archive is called
	MasterKey keySeed     // seed from which shard encryption keys are derived
	MinShards int         // number of shards required to recover file
	Hosts     []hostdb.HostPublicKey
}

type keySeed [32]byte

// MarshalJSON implements the json.Marshaler interface.
func (s keySeed) MarshalJSON() ([]byte, error) {
	return []byte(`"` + hex.EncodeToString(s[:]) + `"`), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (s *keySeed) UnmarshalJSON(b []byte) error {
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

// An EncryptionKey can encrypt and decrypt segments, where each segment is a
// []byte with len proto.SegmentSize.
type EncryptionKey interface {
	EncryptSegments(ciphertext, plaintext []byte, startIndex uint64)
	DecryptSegments(plaintext, ciphertext []byte, startIndex uint64)
}

// chachaKey implements EncryptionKey using ChaCha20.
type chachaKey struct {
	*chacha.Cipher
}

func (c chachaKey) EncryptSegments(ciphertext, plaintext []byte, startIndex uint64) {
	if len(plaintext)%proto.SegmentSize != 0 {
		panic("plaintext must be a multiple of segment size")
	} else if len(plaintext) != len(ciphertext) {
		panic("plaintext and ciphertext must have same length")
	}
	c.SetCounter(startIndex)
	c.XORKeyStream(ciphertext, plaintext)
}
func (c chachaKey) DecryptSegments(plaintext, ciphertext []byte, startIndex uint64) {
	c.EncryptSegments(plaintext, ciphertext, startIndex)
}

// EncryptionKey returns the encryption key used to encrypt sectors in a given
// shard.
func (m *MetaIndex) EncryptionKey(shardIndex int) EncryptionKey {
	// We derive the per-shard encryption key as H(masterKey|shardIndex).
	// Since there's no danger of reuse, we can use an arbitrary nonce.
	//
	// NOTE: as far as I can tell, this isn't any more secure than using
	// m.MasterKey directly with shardIndex as the nonce. Deriving an entirely
	// separate key only prevents an attacker who knows one key from deriving
	// the others. But as long as ChaCha20 remains secure, this scenario is
	// highly unlikely; protecting the master key is all that really matters.
	// Still, I don't see any harm in deriving a separate key, and it's what
	// Sia has always done, so we'll follow suit.
	b := make([]byte, len(m.MasterKey)+8)
	copy(b, m.MasterKey[:])
	binary.LittleEndian.PutUint64(b[len(m.MasterKey):], uint64(shardIndex))
	key := blake2b.Sum256(b)
	c, err := chacha.NewCipher(make([]byte, chacha.NonceSize), key[:], 20)
	if err != nil {
		panic(err)
	}
	return chachaKey{c}
}

// MaxChunkSize returns the maximum amount of file data that can fit into a
// chunk. A chunk is a buffer of file data pre-erasure coding. When the chunk
// is encoded, it is split into len(m.Hosts) shards of equal size. Thus the
// MaxChunkSize is the size of such a buffer that results in shards equal to
// proto.SectorSize. MaxChunkSize is NOT guaranteed to match the actual chunk
// size used in the shard files of m.
func (m *MetaIndex) MaxChunkSize() int64 {
	return proto.SectorSize * int64(m.MinShards)
}

// MinChunks returns the minimum number of chunks required to fully upload the
// file. It assumes that each SectorSlice will reference a full sector
// (proto.SectorSize bytes).
func (m *MetaIndex) MinChunks() int64 {
	n := m.Filesize / m.MaxChunkSize()
	if m.Filesize%m.MaxChunkSize() != 0 {
		n++
	}
	return n
}

// ErasureCode returns the erasure code used to encode and decode the shards
// of m.
func (m *MetaIndex) ErasureCode() ErasureCoder {
	return NewRSCode(m.MinShards, len(m.Hosts))
}

// Archive concatenates the meta file index with its referenced shard files and
// writes the resulting gzipped tar archive to filename.
func (m *MetaFile) Archive(filename string) error {
	// sync files in workdir before creating archive; otherwise a crash could
	// leave us in an inconsistent state
	syncPath := func(path string) error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		return f.Sync()
	}

	if err := syncPath(filepath.Join(m.Workdir, indexFilename)); err != nil {
		return errors.Wrap(err, "could not sync workdir")
	}
	for _, h := range m.Hosts {
		if err := syncPath(m.ShardPath(h)); err != nil {
			return errors.Wrap(err, "could not sync workdir")
		}
	}

	f, err := os.Create(filename)
	if err != nil {
		return errors.Wrap(err, "could not create archive")
	}
	defer f.Close()
	zip := gzip.NewWriter(f)
	tw := tar.NewWriter(zip)

	// set ModTime
	m.ModTime = time.Now()

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
	for _, h := range m.Hosts {
		b, err := os.Open(m.ShardPath(h))
		if err != nil {
			return errors.Wrap(err, "could not open archive shard")
		}
		defer b.Close()
		stat, err := b.Stat()
		if err != nil {
			return errors.Wrap(err, "could not stat shard")
		}
		err = tw.WriteHeader(&tar.Header{
			Name: filepath.Base(b.Name()),
			Size: stat.Size(),
			Mode: int64(stat.Mode()),
		})
		if err != nil {
			return errors.Wrap(err, "could not write shard header")
		} else if _, err = io.Copy(tw, b); err != nil {
			return errors.Wrap(err, "could not add shard to archive")
		}
	}

	// flush tar data
	if err := tw.Close(); err != nil {
		return errors.Wrap(err, "could not write tar data")
	}

	// flush gzip data
	if err := zip.Close(); err != nil {
		return errors.Wrap(err, "could not write gzip data")
	}

	// ensure durability
	if err := f.Sync(); err != nil {
		return errors.Wrap(err, "could not sync archive file")
	}

	// remove workdir
	if err := os.RemoveAll(m.Workdir); err != nil {
		return errors.Wrap(err, "could not clean up working directory")
	}
	return nil
}

// ShardPath returns the canonical path on disk of a shard associated with the
// given hostKey.
func (m *MetaFile) ShardPath(hostKey hostdb.HostPublicKey) string {
	return filepath.Join(m.Workdir, hostKey.Key()+".shard")
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

// ReplaceHost replaces a host within the meta file. The shard file
// corresponding to the replaced host is not deleted until m.Archive is
// called.
func (m *MetaFile) ReplaceHost(oldHostKey, newHostKey hostdb.HostPublicKey) bool {
	for i, h := range m.Hosts {
		if h == oldHostKey {
			m.Hosts[i] = newHostKey
			return true
		}
	}
	return false
}

// NewMetaFile creates a meta file using the specified contracts and erasure-
// coding parameters. The meta file is returned in extracted state, meaning a
// temporary directory will be created to hold the archive contents. This
// directory will be removed when Archive is called on the meta file.
func NewMetaFile(filename string, mode os.FileMode, size int64, contracts ContractSet, minShards int) (*MetaFile, error) {
	if minShards > len(contracts) {
		return nil, errors.New("minShards cannot be greater than the number of contracts")
	}
	hostIndex := make(map[hostdb.HostPublicKey]int)
	hosts := make([]hostdb.HostPublicKey, 0, len(contracts))
	for key := range contracts {
		hostIndex[key] = len(hosts)
		hosts = append(hosts, key)
	}
	// create workdir
	workdir := filename + "_workdir"
	err := os.MkdirAll(workdir, 0700)
	if err != nil {
		return nil, errors.Wrap(err, "could not create working directory")
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
		hostIndex: hostIndex,
		Workdir:   workdir,
	}
	fastrand.Read(m.MasterKey[:])
	// create index file
	indexFile, err := os.Create(filepath.Join(workdir, indexFilename))
	if err != nil {
		os.RemoveAll(workdir)
		return nil, errors.Wrap(err, "could not create index file")
	}
	defer indexFile.Close()
	if err := json.NewEncoder(indexFile).Encode(m.MetaIndex); err != nil {
		os.RemoveAll(workdir)
		return nil, errors.Wrap(err, "could not write index file")
	}
	// create shard files
	for _, h := range hosts {
		f, err := os.Create(m.ShardPath(h))
		if err != nil {
			os.RemoveAll(workdir)
			return nil, errors.Wrap(err, "could not create shard file")
		}
		f.Close()
	}

	return m, nil
}

// ExtractMetaFile extracts an existing meta file archive. Like NewMetaFile,
// it creates a temporary directory to hold the extracted files.
func ExtractMetaFile(filename string) (_ *MetaFile, err error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, errors.Wrap(err, "could not open archive")
	}
	defer f.Close()

	// check that we aren't clobbering an existing workdir
	workdir := filename + "_workdir"
	if _, err := os.Stat(workdir); err == nil {
		return nil, errors.New("refusing to overwrite " + workdir)
	}

	// create working directory
	err = os.MkdirAll(workdir, 0700)
	if err != nil {
		return nil, errors.Wrap(err, "could not create working directory")
	}
	defer func() {
		if err != nil {
			os.RemoveAll(workdir)
		}
	}()

	// decode index and extract shards to workdir
	var index MetaIndex
	zip, err := gzip.NewReader(f)
	if err != nil {
		return nil, errors.Wrap(err, "could not read gzip header")
	}
	tr := tar.NewReader(zip)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			if index.Version == 0 {
				return nil, errors.New("archive is missing an index")
			}
			break
		} else if err != nil {
			return nil, errors.Wrap(err, "could not read archive entry")
		}

		if hdr.Name == indexFilename {
			// copy index to file and simultaneously read into memory
			indexFile, err := os.Create(filepath.Join(workdir, indexFilename))
			if err != nil {
				return nil, errors.Wrap(err, "could not create index file")
			}
			defer indexFile.Close()
			tee := io.TeeReader(tr, indexFile)
			if err = json.NewDecoder(tee).Decode(&index); err != nil {
				return nil, errors.Wrap(err, "could not process index file")
			}
		} else {
			// copy shard to file
			bf, err := os.Create(filepath.Join(workdir, hdr.Name))
			if err != nil {
				return nil, errors.Wrap(err, "could not create shard file")
			}
			defer bf.Close()
			if _, err = io.Copy(bf, tr); err != nil {
				return nil, errors.Wrap(err, "could not write shard file")
			}
		}
	}

	if err := zip.Close(); err != nil {
		return nil, errors.Wrap(err, "archive is corrupted")
	}

	// initialize hostIndex
	hostIndex := make(map[hostdb.HostPublicKey]int)
	for i, h := range index.Hosts {
		hostIndex[h] = i
	}

	return &MetaFile{
		MetaIndex: index,
		hostIndex: hostIndex,
		Workdir:   workdir,
	}, nil
}

// ReadMetaIndex returns the index of a meta file without extracting it.
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
		return index, nil
	}
	return MetaIndex{}, errors.New("archive is missing an index")
}

// ReadMetaFileContents returns the meta file's index and shard slice data.
func ReadMetaFileContents(filename string) (MetaIndex, [][]SectorSlice, error) {
	f, err := os.Open(filename)
	if err != nil {
		return MetaIndex{}, nil, errors.Wrap(err, "could not open archive")
	}
	defer f.Close()
	zip, err := gzip.NewReader(f)
	if err != nil {
		return MetaIndex{}, nil, errors.Wrap(err, "could not read gzip header")
	}
	tr := tar.NewReader(zip)

	var index MetaIndex
	var slices [][]SectorSlice
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			if index.Version == 0 {
				return MetaIndex{}, nil, errors.New("archive is missing an index")
			}
			break
		} else if err != nil {
			return MetaIndex{}, nil, errors.Wrap(err, "could not read archive entry")
		}

		if hdr.Name == indexFilename {
			// read index
			if err = json.NewDecoder(tr).Decode(&index); err != nil {
				return MetaIndex{}, nil, errors.Wrap(err, "could not decode index")
			}
			continue
		} else {
			// read slices
			bs := make([]SectorSlice, hdr.Size/SectorSliceSize)
			if err = binary.Read(tr, binary.LittleEndian, &bs); err != nil {
				return MetaIndex{}, nil, errors.Wrap(err, "could not read shard")
			}
			slices = append(slices, bs)
		}
	}

	if err := zip.Close(); err != nil {
		return MetaIndex{}, nil, errors.Wrap(err, "archive is corrupted")
	}

	return index, slices, nil
}

// MetaFileFullyUploaded reads a meta file without extracting it, reporting
// whether it has been fully uploaded.
func MetaFileFullyUploaded(filename string) (bool, error) {
	index, shards, err := readMetaFileShards(filename)
	if err != nil {
		return false, err
	}
	return shards == len(index.Hosts), nil
}

// MetaFileCanDownload reads a meta file without extracting it, reporting
// whether it can be downloaded.
func MetaFileCanDownload(filename string) (bool, error) {
	index, shards, err := readMetaFileShards(filename)
	if err != nil {
		return false, err
	}
	return shards >= index.MinShards, nil
}

// readMetaFileShards reads a meta file and returns its index and the number of
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
			var s SectorSlice
			var shardSize int64
			err = binary.Read(tr, binary.LittleEndian, &s)
			for err != io.EOF {
				shardSize += int64(s.Length)
				err = binary.Read(tr, binary.LittleEndian, &s)
			}
			if err != io.EOF {
				return MetaIndex{}, 0, err
			}
			shardSizes = append(shardSizes, shardSize)
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
