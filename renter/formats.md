## Formats

The `renter` package defines two important formats: one for storing contract
metadata, and one for storing file metadata.

### contract

A contract defines a file contract formed with a host. It contains the
contract's ID, the contract transaction, the secret key used to revise the
transaction, and the Merkle roots of each 4MB sector stored under the
contract, i.e. the set of hashes whose Merkle hash is the contract's
`FileMerkleRoot`.

To ensure high throughput, the format enables efficient updates to both the
contract transaction and the sector Merkle roots. Since the size of the
transaction may change (e.g. when the `NewFileSize` field increases), the
format stores the transaction in a fixed-size "arena", padded with zeros. Thus
the sector Merkle roots always begin at a fixed offset, making it trivial to
retrieve or modify a given root. (Note that the sector Merkle roots will be
constitute the bulk of the file; a 1 TB contract requires 8 MB of Merkle
roots.)

```go
type Contract struct {
	// binary
	Magic   [11]byte // the string 'us-contract'
	Version byte     // version of the contract format, currently 1
	ID      [32]byte // the ID of the contract
	Key     [64]byte // the secret ed25519 key used to sign revisions

	// JSON
	Transaction types.Transaction // contract transaction (see Sia/types)

	// padding until byte 4096...

	// binary
	SectorRoots [][32]byte
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
	Version   int      // version of the file format, currently 1
	Filesize  int64    // original file size
	Mode      uint32   // mode bits
	ModTime   string   // RFC 3339 timestamp
	MasterKey string   // seed from which shard encryption keys are derived
	MinShards int      // number of shards required to recover file
	Hosts     []string // public key of each host
}
```

As of version 1, files are encoded with Reed-Solomon and encrypted with XTS-AES.
See the reference implementation for the details of how encryption keys are
derived and how files are split into erasure-coded shards.

The order of the `Hosts` field is significant. Specifically, the index of a
host is also its shard index in the erasure encoding.

### shard

A shard is a binary array of slices. Each slice uniquely identifies a
contiguous slice of a sector stored on a host by specifying the Merkle root of
the sector, an offset within it, and a length. The shard as a whole represents
a contiguous slice of data that may span many sectors. As such, the order of
the array is significant.

Each slice also includes a checksum of the original data (before encryption).
As of version 1, the checksum is a BLAKE-2b hash. The checksum serves two
purposes: it assures data integrity when downloading, and it allows for
comparisons between a local file and a metafile. For example, when resuming a
download, the checksums can be used to determine which slices have already
been downloaded.

```go
type Shard []SectorSlice

type SectorSlice struct {
	MerkleRoot [32]byte
	Offset     uint32
	Length     uint32
	Checksum   [32]byte
}
```
