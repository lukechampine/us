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
**`siad` must be v1.3.5 or higher.**

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

You will also want to create a config file, `~/.config/us/user.toml`. An example is
provided below:

```toml
# API port of siad.
# OPTIONAL. Default: "localhost:9980"
siad_addr = "localhost:1993"

# API password of siad. If not defined, user will attempt to read the standard
# siad password file, ~/.sia/apipassword.
# OPTIONAL. Default: ""
siad_password = "foobarbaz"

# Directory where contracts are stored. An absolute path is recommended.
# OPTIONAL. Default: "~/.config/us/contracts-available"
contracts_available = "~/us/available"

# Directory where enabled contracts are stored. This directory should contain
# only symlinks to the contracts folder. An absolute path is recommended.
# OPTIONAL. Default: "~/.config/us/contracts-enabled"
contracts_enabled = "~/us/enabled"

# Minimum number of hosts required to download a file. Also controls
# file redundancy: uploading to 40 hosts with min_shards = 10 results
# in 4x redundancy.
# REQUIRED (unless the -m flag is passed to user).
min_shards = 10

# log file. If defined, various statistics will be written to this file in
# JSON format. An absolute path is recommended.
# OPTIONAL. Default: ""
log_file = "~/us/log"
```

A more minimal example, using defaults for most values, is:

```toml
min_shards = 10
log_file = "~/.config/us/log"
```


## Scanning for Hosts

The first step of forming a contract is choosing a host to form the contract
with. You can get a ranked list of hosts by running `siac hostdb -v`.
The longer `siad` has been running, the more accurate these rankings will be.

The command will output a ranked list of hosts, with the best-scoring hosts at
the bottom. The format of each line is:

```
[rank]: [host public key] [IP address] [score] [storage price] [download price] [uptime]
```

The format of host public keys is:

```
ed25519:706715a4f37fda29f8e06b867c5df3f139f6ed93c18d99a5665eb66a5fab6009
```

You can pass this full string to the `user` commands below, but it is
generally more convenient to use the abbreviated form. In the abbreviated
form, the `ed25519:` prefix is dropped, and only the first few characters of
the key are retained. The key above, for example, could be shortened to
`706715a4`. Like git hashes, you only need enough characters to ensure that
the key is unambiguous; eight is a safe choice.


## Forming Contracts

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
the resulting contract ID. The file will be stored in the `contracts_available`
directory, and the contract is automatically enabled by creating a symlink in
the `contracts_enabled` directory.

Note that `funds` does not include the transaction fee, the host's contract
feeor the siafund tax. `funds` is simply the number of coins in the renter's
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


## Renewing Contracts

Once you have a contract, renewing is easy:

```bash
$ user renew [contract] [funds] [endheight] [newcontract]
```

`contract` is the path of the original contract metadata file, and
`newcontract` is where the new contract metadata will be written. If
`newcontract` is not supplied, the new contract will be written to a file
named according to the same scheme as `user form`.

When a contract is renewed, the new contract is automatically enabled and the
old contract is disabled (if applicable). Lastly, a suffix, `_old`, is also
appended to the filename of the old contract to ensure that it will no longer
be used.

The host may be offline when you attempt to renew, in which case you will have
to try again later. For this reason, it is recommended that you first attempt
to renew a contract within at least 1000 blocks (approx. 1 week) of its end
height.


## Uploading and Downloading Files

`user` stores and retrieves files using *metafiles*, which are small files
containing the metadata necessary to retrieve and update a file stored on a
host. Uploading a file creates a metafile, and downloading a metafile creates
a file. Metafiles can be download by anyone possessing contracts with at least
`min_shards` of the file's hosts. Thus metafiles can be freely shared with
other users. To share multiple files, bundle their corresponding metafiles in
an archive such as a `.tar` or `.zip`.

The upload and download commands are straightforward:

```bash
$ user upload [file] [metafile]

$ user download [metafile] [file]
```

`file` is the path of the file to be read (during upload) or written (during
download), and `metafile` is the path where the file metadata will be written.
The extension for metafiles is `.usa` (`a` for "archive"). Both commands use
the `contracts_enabled` directory specified in `user.toml` or by the `-c`
flag.

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


## Blacklisting Hosts

Sia's design assumes that hosts may fail or provide poor quality of service.
If a host goes offline, transfers data too slowly, raises their prices too
high, etc., naturally we would like to blacklist them. This is as simple as:

```bash
$ user contracts disable [hostkey]
```

Disabling a contract does not delete it permanently; the actual contract file
remains in the `contracts-available` directory. This command simply removes
the corresponding symlink in the `contracts-enabled` directory.

Of course, if you blacklist too many hosts, you may not be able to download
your files from the remaining set. To re-enable a contract, run:

```bash
$ user contracts enable [hostkey]
```

As expected, this command simply recreates a symlink in the `contracts-enabled`
directory.

The use of symlinks allows you to create multiple sets of enabled contracts
and quickly switch between them. For example, you could have a directory
called `contracts-cheap` that references the cheapest hosts, and another
directory called `contracts-fast` that references the fastest hosts. You can
then pass the `-c` flag to `user` to switch between these sets at will.


## Migrating Files

Blacklisting hosts will improve your quality of service, but it also reduces
the redundancy of your files. In the long-term, it is safest to re-upload your
data to better hosts. In `us`, this process is called "migration."

There are three ways to migrate a file, depending on how you obtain the data
that will be uploaded to the new hosts. If you have a copy of the original
file, you can simply use that data. Alternatively, if you are able and willing
to download from the bad hosts, you can get the data that way. Finally, if you
don't have a copy of the file and the bad hosts are offline, too expensive, or
too slow, you can download from just the good hosts and then reconstruct the
missing redundancy. In `user`, these options are called `file`, `direct`, and
`remote`, respectively. `file` is the cheapest and fastest option; `remote` is
the slowest and most expensive, but is often the only choice; and `direct` may
be better or worse than `remote` depending on the quality of the bad hosts.

Let's assume that you uploaded a file to three hosts with `min_shards = 2`,
and one of them is now unresponsive. You would like to repair the missing
redundancy by migrating the shard on the unresponsive host to a new host.
First, if you haven't already done so, blacklist the old host by running:

```bash
$ user contracts disable [hostkey]
```

Next, form a new contract with the new host. (The new contract will be enabled
automatically.) Now, you can perform the actual migration. If you had a copy
of the original file, you could run:

```bash
$ user migrate -file=[file] [metafile]
```

Unfortunately, in this example, you do not have the original file.

If the old host were not unresponsive, you could run:

```bash
$ user migrate -direct [metafile]
```

Unfortunately, in this example, the host is unresponsive.

However, there are two good hosts available, so you can download their shards
and use them to reconstruct the third shard by running:

```bash
$ user migrate -remote [metafile]
```

All three migration options can be resumed if interrupted, and can also be
applied to directories.


## Using a SHARD Server

`user` can talk to a SHARD server to learn the current blockheight and lookup
host IP addresses. Forming and renewing contracts still requires `siad`, but
once you have contracts, a SHARD server allows you to upload and download
without needing to communicate with a full consensus node. You can run your
own SHARD server, or talk to a public instance, although the latter carries
some risk: the server may lie to you about the current blockheight and/or the
most recent IP announced by a given host (although it cannot lie about *which*
IP the host announced). To reduce risk, querying multiple public instances is
recommended.

To configure `user` to talk to a SHARD server, simply add its address to your
`user.toml`, e.g.:

```toml
shard_addr = "12.34.56.78"
```

`user` will then use the SHARD server when it can, and `siad` otherwise.

---

**WARNING:** `user` requires exclusive access to your contract files. That is,
you generally can't run two instances of `user` at the same time, because they
will both attempt to modify the same contract file. To avoid this problem, you
must either use a synchronization mechanism (such as a lockfile) to serialize
access to contracts, or ensure that each instance of `user` accesses a
different set of contracts. Remember, `user` is intended to be a user-facing
tool; if your intent is to build more complex apps, then importing the `us`
packages directly is the recommended approach.
