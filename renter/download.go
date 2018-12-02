package renter

import (
	"bytes"

	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renter/proto"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/modules"
	"golang.org/x/crypto/blake2b"
)

// ErrBadChecksum indicates that a piece of sector data failed checksum
// validation.
var ErrBadChecksum = errors.New("sector data failed checksum validation")

// A HostKeyResolver resolves a host's public key to the most recent
// NetAddress it announced on the blockchain.
type HostKeyResolver interface {
	ResolveHostKey(pubkey hostdb.HostPublicKey) (modules.NetAddress, error)
}

// A ShardDownloader wraps a proto.Downloader to provide SectorSlice-based
// data retrieval, transparently decrypting and validating the received data.
type ShardDownloader struct {
	Downloader *proto.Downloader
	Slices     []SectorSlice
	Key        EncryptionKey
	buf        bytes.Buffer
}

// DownloadAndDecrypt downloads the SectorSlice associated with chunkIndex.
// The data is decrypted and validated before it is returned. The returned
// slice is only valid until the next call to DownloadAndDecrypt.
func (d *ShardDownloader) DownloadAndDecrypt(chunkIndex int64) ([]byte, error) {
	if chunkIndex >= int64(len(d.Slices)) {
		return nil, errors.Errorf("unknown chunk index %v", chunkIndex)
	}
	s := d.Slices[chunkIndex]
	offset := s.SegmentIndex * merkle.SegmentSize
	length := s.NumSegments * merkle.SegmentSize
	// resize buffer and download
	d.buf.Reset()
	d.buf.Grow(int(length))
	data := d.buf.Bytes()[:length]
	err := d.Downloader.PartialSector(data, s.MerkleRoot, offset)
	if err != nil {
		return nil, err
	}
	// decrypt segments
	//
	// NOTE: to avoid reusing the same segment index for multiple encryptions,
	// we use chunkIndex * SegmentsPerSector as the starting index. See
	// SectorBuilder.Append.
	startIndex := uint64(chunkIndex * merkle.SegmentsPerSector)
	d.Key.DecryptSegments(data, data, startIndex)
	// validate checksum
	if blake2b.Sum256(data) != s.Checksum {
		return nil, ErrBadChecksum
	}
	return data, nil
}

// HostKey returns the public key of the host.
func (d *ShardDownloader) HostKey() hostdb.HostPublicKey {
	return d.Downloader.HostKey()
}

// Close closes the connection to the host.
func (d *ShardDownloader) Close() error {
	return d.Downloader.Close()
}

// NewShardDownloader connects to a host and returns a ShardDownloader capable
// of downloading the SectorSlices of m.
func NewShardDownloader(m *MetaFile, contract *Contract, hkr HostKeyResolver) (*ShardDownloader, error) {
	hostKey := contract.HostKey()
	// load sector slices
	slices, err := ReadShard(m.ShardPath(hostKey))
	if err != nil {
		return nil, errors.Wrapf(err, "%v: could not load sector slices", hostKey.ShortKey())
	}
	// get host IP
	hostIP, err := hkr.ResolveHostKey(contract.HostKey())
	if err != nil {
		return nil, errors.Wrapf(err, "%v: could not resolve host key", hostKey.ShortKey())
	}
	// create downloader
	d, err := proto.NewDownloader(hostIP, contract)
	if err != nil {
		return nil, errors.Wrapf(err, "%v: could not initiate download protocol with host", hostKey.ShortKey())
	}
	return &ShardDownloader{
		Downloader: d,
		Key:        m.EncryptionKey(m.HostIndex(hostKey)),
		Slices:     slices,
	}, nil
}
