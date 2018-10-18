# Developing with `us`

The `us` project is a new interface to Sia. Because the project introduces
some new concepts and file formats, it's important to understand how
everything fits together. Learning about the system will make it vastly easier
to leverage in your own projects. That way, if something goes wrong, you'll
have the knowledge and tools to understand what happened and how to fix it.

This document assumes that you are writing Go code that directly imports `us`
packages. If you just want to work with `us` formats, see their specifications
[here](renter/formats.md).

## Prerequisites

You will need a Go toolchain (1.10 or higher) and an instance of `siad`
(v1.3.5 or higher). Check that you can build `user` by running `make` from the
top-level `us` directory.

Integration testing usually involves talking to Sia hosts. You can use real
hosts (and real siacoins) for this, or a testnet via [Sia-Ant-Farm](https://gitlab.com/NebulousLabs/Sia-Ant-Farm).
A new tool for easily setting up renter-host testnets is forthcoming.

## Architecture

In this section, we'll step through the building blocks of the project,
starting at the lowest level (protocols and formats) and building up to the
`user` command-line tool. It is not a full description of each layer; for
that, you'll need to read the code. Instead, each section contains only the
most important ideas from that layer, giving you the context you need to
develop your own apps or contribute to `us`.


### `renter/proto`

The `proto` package implements the Sia renter-host protocol, which facilitates
the exchange of file data and the revision of the file contract. After some
initial setup (including specifying which contract the renter intends to
modify), the protocol is basically a loop. When uploading, the renter sends
the data to be uploaded, and then a new revision of the file contract that
pays for the data. If the host accepts the contract, it writes the data to
disk and returns a signed version of the contract. This completes one
iteration of the loop. When downloading, the order is reversed: the renter
sends the revised contract along with the download request, and then the host
replies with the signed contract, followed by the requested data.

The basic unit of uploading and downloading is the *sector*. A sector is a
`[]byte` whose size is given by `renterhost.SectorSize`, which is `1 << 22`
bytes (4 MiB). When uploading, the renter must send a full sector. When
downloading, the renter specifies the *Merkle root* of the sector it wants to
download, along with an offset and length. This allows the renter to download
less than a full sector, which is crucial when downloading small files.

When performing the renter-host protocol, the contract in question must be
repeatedly updated to reflect the most recent revision. And since the renter
and host need to stay synchronized even if the connection is interrupted or
the power goes out, these contract updates should be committed to durable
storage. To facilitate this, the `proto` package exposes a `ContractEditor`
interface, whose methods are called at specific points in the protocol.

The `proto` package exposes two objects for executing the renter-host
protocol: `proto.Uploader` and `proto.Downloader`.

### `renter`

The `renter` package builds on `proto`'s sector-based operations in order to
provide file-based operations. It has three core elements:

- A format for storing file contracts
- A format for storing file metadata
- Helper objects that update these formats in tandem with the renter-host protocol

The contract format has the extension `.contract`. It contains the file
contract for a particular host, alongside the Merkle roots of each sector that
was uploaded to that host via the contract. The `Contract` type that
encapsulates this format satisfies the `proto.ContractEditor` interface; when
a `proto.Uploader` uploads a sector, for example, it calls the `AppendRoot`
method of `Contract`, which writes the Merkle root of that sector to the
`.contract` file.

The metadata format is called a "metafile" and has the extension `.usa`. It
contains standard file metadata (size, mode bits, modtime), as well as
metadata specifying the erasure code and master encryption key. Finally, it
contains a set of `.shard` files, one for each host, that collectively specify
which slices of sector data comprise the file.

A full description of both formats is available [here](renter/formats.md).

The `renter` package exposes two objects that integrate these new formats with
the renter-host protocol: `ShardUploader` and `ShardDownloader`. These objects
wrap the `proto.Uploader` and `proto.Downloader` types; in addition to
updating the `.contract` file, they also update the `.shard` file associated
with the host, and transparently encrypt/decrypt the data being stored. For
example, when calling `ShardUploader.EncryptAndUpload`, three things happen:

1. The sector is encrypted and sent to the host, along with a contract revision signed by the renter
2. The host signs and returns the contract revision, which is then written to the `.contract` file, along with the Merkle root of the sector
3. The renter updates the `.shard` file to record the Merkle root of the sector

In order to upload a file, first call `NewMetaFile` to create the metafile
with the desired size, mode bits, redundancy, etc. Then connect to each host
using `NewShardUploader`. Next, read in a *chunk* of file data and split it
into sectors using the desired erasure code. Then use the `EncryptAndUpload`
method to upload each sector. Repeat this process until the file has been
fully uploaded, and then call `Close` on the metafile and each uploader.

Downloading is the inverse. Open the metafile with `OpenMetaFile`, and then
connect to each host using `NewShardDownloader`. Call `DownloadAndDecrypt` on
each host, and use the metafile's erasure code to reconstruct the original
file data and write it to disk. Repeat this process for each chunk that was
uploaded previously, and then call `Close` on the metafile and each downloader.

It's important to keep in mind that metafiles are archives, and so modifying
them typically requires extracting the archive into a temporary directory. If
the modification process is interrupted, this "workdir" may be left behind in
an inconsistent state. See `cmd/user/recover.go` for examples of how to recover
such states. When downloading, it is typically easier and safer to read the
entire metafile into memory with `ReadMetaFileContents` rather than extracting
it, since no modifications are necessary.

### `renter/renterutil`

The `renterutil` package builds on `renter` to provide easy-to-use functions
for uploading and downloading entire files, as well as migrating file data
from one host to another. These operations live in `renterutil` (rather than
`renter`) because their implementation is necessarily opinionated. For
example, when downloading, only a subset of the hosts are necessary to recover
the file; which hosts should be used? Should they all be tried in parallel,
selecting only the fastest? Or should the cheapest hosts be tried first,
falling back to more expensive hosts as needed? The answer varies based on the
circumstances and requirements of the renter, and the same is true for
uploading and migrating. `renterutil` is therefore intended to provide
implementations that are acceptable for the common case, while also serving as
a reference for developers looking to optimize the operations for a specific
use-case.


### `user`

Finally we arrive at `user`, a command-line interface for managing Sia
contracts and files. `user` loads contracts and files using `renter`, and then
passes them to `renterutil` functions that perform various user-initiated
operations. Like `renterutil`, it prioritizes ease-of-use over absolute
customization, and serves as a reference to inspire more sophisticated tools.

In order to form contracts and learn the IP addresses of hosts, `user` must
talk to an instance of `siad`. This dependency is intentionally minimal; it
means that `user` can easily be modified to talk to a different daemon, or
even a centralized service. Use `renterutil.NewSiadClient` to create a client
that talks to `siad`.

---

Now that you understand the principles behind the `us` project, you are ready
to start building your own project on top of the `us` packages. If you run
into anything surprising or confusing, please contribute back to this guide to
make things easier for those who come after you!
