## Formats

The `renter` package defines a format for storing file metadata, called a
*metafile*. A metafile is a gzipped tar archive containing one index file
(always named `index`) followed by one or more shard files (each named after
their host's public key, plus a `.shard` suffix). The order of the shard files
is unspecified.

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

## Contracts

`us` previously defined a format for file contracts, but this functionality
has been superseded by [`muse`](https://github.com/lukechampine/muse). If you
need to store contracts on disk, marshalling the `renter.Contract` type to
binary or JSON should work fine. If you want to really want to use the old
format, you can find it [here](https://github.com/lukechampine/us/blob/3428b9c63ce0d7a339f2ecaaa794fa08ddb55434/renter/contracts.go#L34-L81).
