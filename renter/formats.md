## Formats

The `renter` package defines two important formats: one for storing contract
metadata, and one for storing file metadata.

### contract

A contract defines a file contract formed with a host. It contains the host's
public key, the contract's ID, the secret key used to revise the contract, and
the latest revision of the contract (along with signatures). All of the fields
are encoded in binary.

The revision and signatures are overwritten after each revision. This can result
in corruption, but if corruption occurs, the revision and signatures can simply
be redownloaded from the host. The host's public key, the contract ID, and the
secret key are never written to after the contract is initially created, so they
cannot become corrupted.

A contract file may contain trailing "garbage" bytes. This can occur if a new
revision is written which requires fewer bytes than a prior revision. Decoders
should halt after decoding the signatures, leaving trailing garbage unexamined.

```go
type Contract struct {
	Magic   [11]byte // the string 'us-contract'
	Version byte     // version of the contract format, currently 3
	HostKey [32]byte // the ed25519 public key of the host
	ID      [32]byte // the ID of the contract
	Key     [32]byte // the ed25519 private key of the renter

	// latest contract revision, with signatures (see Sia/types)
	Revision   types.FileContractRevision
	Signatures [2]types.TransactionSignature
}
```

### metafile

A metafile is a gzipped tar archive containing one index file (always named
`index`) followed by one or more shard files (each named after their host's
public key, plus a ".shard" suffix). The order of the shard files is
unspecified.

### index

An index is a JSON object containing metadata that pertains to set of shards
which together constitute one encrypted, erasure-coded file.

```go
type Index struct {
	Version   int      // version of the file format, currently 2
	Filesize  int64    // original file size
	Mode      uint32   // mode bits
	ModTime   string   // RFC 3339 timestamp
	MasterKey string   // seed from which shard encryption keys are derived
	MinShards int      // number of shards required to recover file
	Hosts     []string // public key of each host
}
```

As of version 2, files are encoded with Reed-Solomon and encrypted with
XChaCha20. See the reference implementation for the details of how encryption
keys are derived and how files are split into erasure-coded shards.

The order of the `Hosts` field is significant. Specifically, the index of a
host is also its shard index in the erasure code.

### shard

A shard is a binary array of slices. Each slice uniquely identifies a contiguous
slice of a sector stored on a host by specifying the Merkle root of the sector,
an offset within it, a length, and an encryption nonce. The shard as a whole
represents a contiguous slice of data that may span many sectors. As such, the
order of the array is significant.

The offset and length are in terms of segments (64 bytes), which are the
atomic unit of transfer in the Sia renter-host protocol. Storing data thus
requires adding (and later removing) padding.

```go
type Shard []SectorSlice

type SectorSlice struct {
	MerkleRoot   [32]byte
	SegmentIndex uint32
	NumSegments  uint32
	Nonce        [24]byte
}
```
