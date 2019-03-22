package renter

import (
	"bytes"

	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renterhost"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/modules"
)

// ErrBadChecksum indicates that a piece of sector data failed checksum
// validation.
var ErrBadChecksum = errors.New("sector data failed checksum validation")

// A HostKeyResolver resolves a host's public key to the most recent
// NetAddress it announced on the blockchain.
type HostKeyResolver interface {
	ResolveHostKey(pubkey hostdb.HostPublicKey) (modules.NetAddress, error)
}

// A ShardDownloader wraps a proto.Session to provide SectorSlice-based
// data retrieval, transparently decrypting and validating the received data.
type ShardDownloader struct {
	Downloader *proto.Session
	Slices     []SectorSlice
	Key        KeySeed
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
	err := d.Downloader.Read(&d.buf, []renterhost.RPCReadRequestSection{{
		MerkleRoot: s.MerkleRoot,
		Offset:     offset,
		Length:     length,
	}})
	if err != nil {
		return nil, err
	}
	data := d.buf.Bytes()
	// decrypt segments
	xchachaNonce := append(s.Nonce[:], make([]byte, 4)...)
	d.Key.XORKeyStream(data, xchachaNonce, uint64(s.SegmentIndex))
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
	d, err := proto.NewSession(hostIP, contract, 0)
	if err != nil {
		return nil, errors.Wrapf(err, "%v: could not initiate download protocol with host", hostKey.ShortKey())
	}
	return &ShardDownloader{
		Downloader: d,
		Key:        m.MasterKey,
		Slices:     slices,
	}, nil
}
