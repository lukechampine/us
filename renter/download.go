package renter

import (
	"bytes"
	"io"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/modules"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renterhost"
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

type cryptWriter struct {
	w      io.Writer
	slices []SectorSlice
	key    KeySeed
	off    int64
}

func calcSections(slices []SectorSlice, offset, length int64) ([]renterhost.RPCReadRequestSection, error) {
	if offset < 0 || length < 0 {
		return nil, errors.New("offset and length must be positive")
	}
	// seek to offset
	var n int64
	for i := range slices {
		size := int64(slices[i].NumSegments) * merkle.SegmentSize
		if n+size > offset {
			slices = slices[i:]
			break
		}
		n += size
	}
	// construct first section
	var sections []renterhost.RPCReadRequestSection
	s := renterhost.RPCReadRequestSection{
		MerkleRoot: slices[0].MerkleRoot,
		Offset:     slices[0].SegmentIndex*merkle.SegmentSize + uint32(offset-n),
		Length:     slices[0].NumSegments*merkle.SegmentSize - uint32(offset-n),
	}
	sections = append(sections, s)
	length -= int64(s.Length)
	slices = slices[1:]
	// construct remaining sections
	for len(slices) > 0 && length > 0 {
		s := renterhost.RPCReadRequestSection{
			MerkleRoot: slices[0].MerkleRoot,
			Offset:     slices[0].SegmentIndex * merkle.SegmentSize,
			Length:     slices[0].NumSegments * merkle.SegmentSize,
		}
		sections = append(sections, s)
		length -= int64(s.Length)
		slices = slices[1:]
	}
	if length > 0 {
		return nil, errors.New("offset+length is out of bounds")
	}
	// trim final section
	if length < 0 {
		sections[len(sections)-1].Length -= uint32(-length)
	}
	return sections, nil
}

func calcSlices(slices []SectorSlice, off int64) ([]SectorSlice, int64) {
	var n int64
	for i := range slices {
		size := int64(slices[i].NumSegments) * merkle.SegmentSize
		if n+size > off {
			return slices[i:], off - n
		}
		n += size
	}
	return nil, off - n
}

func (cw *cryptWriter) Write(p []byte) (int, error) {
	slices, rem := calcSlices(cw.slices, cw.off)
	b := bytes.NewBuffer(p)
	for i := 0; i < len(slices) && b.Len() > 0; i++ {
		s := slices[i]
		if i == 0 {
			s.SegmentIndex += uint32(rem / merkle.SegmentSize)
		}
		bb := b.Next(int(s.NumSegments) * merkle.SegmentSize)
		cw.key.XORKeyStream(bb, s.Nonce[:], uint64(s.SegmentIndex))
	}
	cw.off += int64(len(p))
	return cw.w.Write(p)
}

// CopySection downloads the requested section of the Shard, decrypts it, and
// writes it to w.
func (d *ShardDownloader) CopySection(w io.Writer, offset, length int64) error {
	sections, err := calcSections(d.Slices, offset, length)
	if err != nil {
		return err
	}
	cw := &cryptWriter{w, d.Slices, d.Key, offset}
	return d.Downloader.Read(cw, sections)
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
