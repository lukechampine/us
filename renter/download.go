package renter

import (
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter/proto"

	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
)

// ErrBadChecksum indicates that a piece of sector data failed checksum
// validation.
var ErrBadChecksum = errors.New("sector data failed checksum validation")

// A ScanFn can scan hosts.
type ScanFn func(hostdb.HostPublicKey) (hostdb.ScannedHost, error)

// A ShardDownloader wraps a proto.Downloader to provide SectorSlice-based data
// retrieval, transparently decrypting and validating the received data.
type ShardDownloader struct {
	Downloader *proto.Downloader
	Slices     []SectorSlice
	Key        EncryptionKey
}

// DownloadAndDecrypt downloads the SectorSlice associated with chunkIndex. The
// data is decrypted and validated before it is returned.
func (d *ShardDownloader) DownloadAndDecrypt(chunkIndex int64) ([]byte, error) {
	if chunkIndex >= int64(len(d.Slices)) {
		return nil, errors.Errorf("unknown chunk index %v", chunkIndex)
	}
	s := d.Slices[chunkIndex]
	// align the offset and length to segment boundaries
	startSegment := s.Offset / proto.SegmentSize
	endSegment := (s.Offset + s.Length) / proto.SegmentSize
	if (s.Offset+s.Length)%proto.SegmentSize != 0 {
		endSegment++
	}
	offset := startSegment * proto.SegmentSize
	length := (endSegment - startSegment) * proto.SegmentSize
	data, err := d.Downloader.PartialSector(s.MerkleRoot, offset, length)
	if err != nil {
		return nil, err
	}
	// decrypt segments
	//
	// NOTE: to avoid reusing the same segment index for multiple encryptions,
	// we use chunkIndex * SegmentsPerSector as the starting index. See
	// SectorBuilder.Append.
	startIndex := uint64(chunkIndex * proto.SegmentsPerSector)
	d.Key.DecryptSegments(data, data, startIndex)
	// trim according to s
	data = data[s.Offset%proto.SegmentSize:][:s.Length]
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
func NewShardDownloader(m *MetaFile, contract *Contract, scan ScanFn) (*ShardDownloader, error) {
	hostKey := contract.HostKey()
	// load sector slices
	slices, err := ReadShard(m.ShardPath(hostKey))
	if err != nil {
		return nil, errors.Wrapf(err, "%v: could not load sector slices", hostKey.ShortKey())
	}
	// get host entry
	host, err := scan(contract.HostKey())
	if err != nil {
		return nil, errors.Wrapf(err, "%v: could not scan host", hostKey.ShortKey())
	}
	// create downloader
	d, err := proto.NewDownloader(host, contract)
	if err != nil {
		return nil, errors.Wrapf(err, "%v: could not initiate download protocol with host", hostKey.ShortKey())
	}
	return &ShardDownloader{
		Downloader: d,
		Key:        m.EncryptionKey(m.HostIndex(hostKey)),
		Slices:     slices,
	}, nil
}
