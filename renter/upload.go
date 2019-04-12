package renter

import (
	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/types"
	"gitlab.com/NebulousLabs/fastrand"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renterhost"
)

// A SectorBuilder facilitates the construction of sectors for later upload.
// SectorBuilders are particularly useful when packing data from multiple
// sources into a single sector. The zero value for a SectorBuilder is an
// empty sector.
type SectorBuilder struct {
	sector    [renterhost.SectorSize]byte
	sectorLen int
	slices    []SectorSlice
}

// Reset resets the SectorBuilder to its initial state.
//
// Reset does not allocate a new sector buffer; since Finish returns a pointer
// to the buffer, this pointer should not be retained after Reset is called.
func (sb *SectorBuilder) Reset() {
	sb.sectorLen = 0
	sb.slices = nil // can't reuse capacity; Slices shares memory
}

// Append appends data to the sector being constructed, encrypting it with the
// given key and chunkIndex. The data must be a multiple of merkle.SegmentSize.
//
// Each call to Append creates a SectorSlice that is accessible via the Slices
// method. This SectorSlice reflects the length and checksum of the original
// (unencrypted) data.
//
// Append panics if len(data) > sb.Remaining().
func (sb *SectorBuilder) Append(data []byte, key KeySeed) {
	if len(data)%merkle.SegmentSize != 0 {
		// NOTE: instead of panicking, we could silently pad the data; however,
		// this is very dangerous, because the SectorSlice will not record the
		// true size of the data, but rather the rounded-up number of segments.
		// Padding is okay at the end of the file, since we can use the filesize
		// to figure out how much padding was added, but padding in the middle
		// of a file is almost certainly a developer error.
		panic("len(data) must be a multiple of merkle.SegmentSize bytes")
	}
	if sb.sectorLen+len(data) > renterhost.SectorSize {
		panic("data exceeds sector size")
	}

	// copy the data into the sector
	sectorSlice := sb.sector[sb.sectorLen:][:len(data)]
	copy(sectorSlice, data)

	// encrypt the data in place
	segmentIndex := sb.sectorLen / merkle.SegmentSize
	var nonce [24]byte
	fastrand.Read(nonce[:])
	key.XORKeyStream(sectorSlice, nonce[:], uint64(segmentIndex))

	// record the new slice and update sectorLen
	sb.slices = append(sb.slices, SectorSlice{
		SegmentIndex: uint32(segmentIndex),
		NumSegments:  uint32(len(sectorSlice) / merkle.SegmentSize),
		Nonce:        nonce,
	})
	sb.sectorLen += len(sectorSlice)
}

// Len returns the number of bytes appended to the sector. Note that, due to
// padding, it is not guaranteed that Len equals the sum of the slices passed
// to Append.
func (sb *SectorBuilder) Len() int {
	return sb.sectorLen
}

// Remaining returns the number of bytes remaining in the sector. It is
// equivalent to renterhost.SectorSize - sb.Len().
func (sb *SectorBuilder) Remaining() int {
	return len(sb.sector) - sb.sectorLen
}

// Finish fills the remaining capacity of the sector with random bytes and
// returns it. The MerkleRoot fields of the SectorSlices tracked by sb are
// also set to the Merkle root of the resulting sector.
//
// After calling Finish, Len returns renterhost.SectorSize and Remaining
// returns 0; no more data can be appended until Reset is called.
//
// Finish returns a pointer to sb's internal buffer, so the standard warnings
// regarding such pointers apply. In particular, the pointer should not be
// retained after Reset is called.
func (sb *SectorBuilder) Finish() *[renterhost.SectorSize]byte {
	fastrand.Read(sb.sector[sb.sectorLen:])
	sb.sectorLen = len(sb.sector)

	// set Merkle root of each slice
	sectorRoot := merkle.SectorRoot(&sb.sector)
	for i := range sb.slices {
		sb.slices[i].MerkleRoot = sectorRoot
	}

	return &sb.sector
}

// Slices returns the SectorSlices present in the sector. One SectorSlice is
// returned for each call to Append since the last call to Reset. Slices
// should only be called after calling Finish; otherwise the MerkleRoot field
// of each SectorSlice will be unset.
func (sb *SectorBuilder) Slices() []SectorSlice {
	return sb.slices
}

// A ShardUploader wraps a proto.Session to provide SectorSlice-based data
// storage, transparently encrypting and checksumming all data before
// transferring it to the host.
type ShardUploader struct {
	Uploader *proto.Session
	Shard    *Shard
	Key      KeySeed
	Sector   SectorBuilder
}

// Upload uploads u.Sector, writing the resulting SectorSlice(s) to u.Shard,
// starting at offset chunkIndex. Upload does not call Reset on u.Sector.
func (u *ShardUploader) Upload(chunkIndex int64) error {
	err := u.Uploader.Write([]renterhost.RPCWriteAction{{
		Type: renterhost.RPCWriteActionAppend,
		Data: u.Sector.Finish()[:],
	}})
	if err != nil {
		return err
	}
	for i, ss := range u.Sector.Slices() {
		if err := u.Shard.WriteSlice(ss, chunkIndex+int64(i)); err != nil {
			return errors.Wrap(err, "could not write to shard file")
		}
	}
	return nil
}

// EncryptAndUpload uploads the data associated with chunkIndex, creating a
// SectorSlice. The data is encrypted and padded to renterhost.SectorSize
// before it is uploaded. The resulting SectorSlice is written to u.Shard.
func (u *ShardUploader) EncryptAndUpload(data []byte, chunkIndex int64) (SectorSlice, error) {
	if len(data) > renterhost.SectorSize {
		return SectorSlice{}, errors.New("data exceeds sector size")
	}
	u.Sector.Reset()
	u.Sector.Append(data, u.Key)
	if err := u.Upload(chunkIndex); err != nil {
		return SectorSlice{}, err
	}
	slices := u.Sector.Slices()
	if len(slices) != 1 {
		panic("expected exactly 1 SectorSlice")
	}
	return slices[0], nil
}

// HostKey returns the public key of the host.
func (u *ShardUploader) HostKey() hostdb.HostPublicKey {
	return u.Uploader.HostKey()
}

// Close closes the connection to the host and the Shard file.
func (u *ShardUploader) Close() error {
	u.Uploader.Close()
	u.Shard.Close()
	return nil
}

// NewShardUploader connects to a host and returns a ShardUploader capable of
// uploading m's data and writing to one of m's Shard files.
func NewShardUploader(m *MetaFile, contract *Contract, hkr HostKeyResolver, currentHeight types.BlockHeight) (*ShardUploader, error) {
	hostKey := contract.HostKey()
	// open shard
	sf, err := OpenShard(m.ShardPath(hostKey))
	if err != nil {
		return nil, errors.Wrapf(err, "%v: could not load shard file", hostKey.ShortKey())
	}
	// get host IP
	hostIP, err := hkr.ResolveHostKey(contract.HostKey())
	if err != nil {
		sf.Close()
		return nil, errors.Wrapf(err, "%v: could not resolve host key", hostKey.ShortKey())
	}
	// create uploader
	u, err := proto.NewSession(hostIP, contract, currentHeight)
	if err != nil {
		sf.Close()
		return nil, errors.Wrapf(err, "%v: could not initiate upload protocol with host", hostKey.ShortKey())
	}
	return &ShardUploader{
		Uploader: u,
		Shard:    sf,
		Key:      m.MasterKey,
	}, nil
}
