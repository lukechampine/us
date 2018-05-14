# user

`user` is a client for `siad`. `user` was created to facilitate three things:

- Scanning hosts
- Forming and renewing contracts with hosts
- Uploading and downloading files to/from hosts

`user` uses the `siad` HTTP API to learn the current block height, lookup host
IP addresses, and sign file contract transactions. Aside from that, `user`
operates completely independently, and communicates with hosts directly. It
saves metadata about contracts and files in simple, efficient formats.
Finally, `user` provides conveniences such as resumable uploads and downloads,
download streaming, and optimizations for small files.

The rest of this document is a guide detailing the functionality of `user`. See
[here](../../renter/formats.md) for a description of the metadata formats.


## Setup

You will need a synchronized `siad` that you can connect to, and a way to
communicate with it -- preferably `siac`, although `curl` will also suffice.

First, identify the port that `siad` is listening on. We will assume `:9980`.
If you do not already have a wallet with coins in it, create one like so:

```bash
$ siac wallet init
Recovery seed:
hurried cement menu mystery... # truncated

$ siac wallet unlock
Wallet password: # enter seed

$ siac wallet address
Created new address: 40b380ebc4f08c43324ff0a9b72da0bf2c73476664a86ad16b48dd696e377a4c0994fc0f3551
# send coins to this address to fund your wallet
```

Lastly, you will want to create a config file, `~/.us/user.toml`. An example is
provided below:

```toml
# API port of siad.
# OPTIONAL. Default: localhost:9980
siad_addr = "localhost:6666"

# directory where contracts are stored.
# OPTIONAL. Default: ~/.us/contracts
contracts = "/home/user/contracts"

# minimum number of hosts required to download a file. Also controls
# file redundancy: uploading to 4 hosts with min_shards = 2 results
# in 2x redundancy.
# REQUIRED.
min_shards = 2

# host pubkey whitelist. If defined, only these hosts will be used
# when uploading or downloading. This is useful if you don't want
# to use all of the contracts in your contracts directory.
# OPTIONAL. Default: []
hosts = [
  "pubkey1",
  "pubkey2",
]
```


## Scanning for hosts

The first step of forming a contract is choosing a host to form the contract
with. You can get a ranked list of hosts by running `siac hosts --verbose`.
The longer `siad` has been running, the more accurate these rankings will be.

You can also scan hosts manually with `user`. The `user scan` command will fetch
the list of all hosts from `siad` and scan them in parallel. Scan results are
printed in real time. Once all the hosts have been scanned, a summary will be
printed that lists the best hosts, as ranked by various metrics.

```bash
$ user scan
Scanning 3 hosts:
Host         Latency     Storage Price    Upload Price    Download Price
a1b2c3        100 ms      360 SC/TB/mo        10 SC/GB          30 SC/GB
d4e5f6        200 ms      120 SC/TB/mo        15 SC/GB          20 SC/GB

Successfully scanned 2 hosts (66% online)

Lowest Latency: (median: 100 ms)
a1b2c3        100 ms      360 SC/TB/mo        10 SC/GB          30 SC/GB
d4e5f6        200 ms      120 SC/TB/mo        15 SC/GB          20 SC/GB

Lowest Storage Price: (median: 120 SC/TB/mo)
d4e5f6        200 ms      120 SC/TB/mo        15 SC/GB          20 SC/GB
a1b2c3        100 ms      360 SC/TB/mo        10 SC/GB          30 SC/GB

# ...
# truncated
```


## Forming contracts

Now, we are ready to form a contract. The command syntax is:

```bash
$ user form [hostkey] [funds] [endheight] [contract]
```

`hostkey` is the public key of the host; `funds` is the amount of siacoins the
contract will store; `endheight` is the height at which the host is no longer
obligated to store the data; and `contract` is the filepath where the contract
metadata file will be written. If `contract` is not supplied, the contract
will be written to `abcdefab-01234567.contract`, where `abcdefab` is the first
four bytes of the host's public key and `01234567` is the first four bytes of
the resulting contract ID. The file will be stored in the contract directory
specified by `user.toml` or the `-c` flag.

If you scanned with `user scan`, the public key of the host is the first column
of output. If you scanned with `siac hosts --verbose`, the public key will be
prefixed with `ed25519:`. Drop this prefix and use the next 6 characters of the
public key as your `hostkey`.

Note that `funds` does not include the transaction fee, the host's contract
fee, or the siafund tax. `funds` is simply the number of coins in the renter's
half of the payment channel, i.e. the amount reserved for paying the host when
uploading and downloading. For convenience, `user` provides a command that
estimates the additional fees:

```bash
$ user scan [hostkey] [filesize] [duration] [downloads]
Data Cost:       1000 SC
Host Fee:         200 SC
Siafund Fee:      100 SC
Transaction Fee:   10 SC
Total:           1310 SC
```

`filesize` is the total amount of data stored, `duration` is the number of
blocks the data is stored for, and `downloads` is the expected number of times
the data will be downloaded. The `Data Cost` field indicates how many siacoins
should be specified when calling `form`, and the `Total` field estimates how
many coins will be spent from the wallet when `form` is called.


## Renewing contracts

Once you have a contract, renewing is easy:

```bash
$ user renew [contract] [funds] [endheight] [newcontract]
```

`contract` is the path of the original contract metadata file, and
`newcontract` is where the new contract metadata will be written. If
`newcontract` is not supplied, the new contract will be written to a file
named according to the same scheme as `user form`.

The host may be offline when you attempt to renew, in which case you will have
to try again later. It is recommended that you renew contracts within at least
1000 blocks of their endheight. This provides a safety buffer if the host is
offline close to the endheight.


## Uploading and Downloading Files

`user` stores and retrieves files using *metafiles*, which are small files
containing the metadata necessary to retrieve and update a file stored on a
host. Uploading a file creates a metafile, and downloading a metafile creates
a file. Metafiles can be freely shared with other users, but are useless
unless the user has contracts with the hosts specified in the metafile. To
share multiple files, add their corresponding metafiles to an archive such as
a `.tar` or `.zip`.

The upload and download commands are straightforward:

```bash
$ user upload [file] [metafile]

$ user download [metafile] [file]
```

`file` is the path of the file to be read (during upload) or written (during
download), and `metafile` is the path where the file metadata will be written.
The extension for metafiles is `.usa` (`a` for "archive"). Both commands use
the contract directory specified in `user.toml` or the `-c` flag. If `user.toml`
specifies a host set, only contracts formed with those hosts will be used.

The `upload` command splits `file` into shards, encrypts each shard with a
different key, and uploads the shards to the host. The `download` command is
the inverse: it downloads shards from each host, decrypts them, and joins the
erasure-coded shards back together, writing the result to `file`. Both
commands modify the contracts involved, and only the most recent modification
of a contract is usable.

Uploads and downloads are resumable. If `metafile` already exists during
upload, or if `file` is smaller than the target filesize during download, then
these commands will pick up where they left off.

You can also upload or download multiple files by specifying a directory path
for both `file` and `metafile`. The directory structure of the metafiles will
mirror the structure of the files. This variant is strongly recommended when
uploading many small files, because it allows `user` to pack multiple files
into a single 4MB sector, which saves lots of bandwidth and money. (Normally,
each uploaded file must be padded to 4MB.)

It is also possible to redirect a download command by dropping the `file`
argument:

```bash
$ user download [contract folder] [metafile] > myfile
```

This forces `user` to download the file in-order. Be aware that this restricts
the parallelism of the download algorithm, and thus may result in slower
speeds.
