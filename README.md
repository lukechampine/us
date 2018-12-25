us
==

[![GoDoc](https://godoc.org/lukechampine.com/us?status.svg)](https://godoc.org/lukechampine.com/us)
[![Go Report Card](https://goreportcard.com/badge/lukechampine.com/us)](https://goreportcard.com/report/lukechampine.com/us)

`us` is an alternative interface to the [Sia](https://gitlab.com/NebulousLabs/Sia)
network. It provides low-level, developer-oriented APIs and formats that
facilitate the storage and retrieval of files on Sia. "Low-level" means that
`us` generally avoids making decisions on behalf of the user. For example,
when renting storage, the user must decide which hosts to form contracts with,
how many coins to spend on each contract, when to renew contracts, when to
migrate data to new hosts, etc. These questions do not have simple answers;
they vary according to the context and goals of the user. Recognizing this,
the `us` philosophy is to provide the user with a set of building blocks
rather than a one-size-fits-all solution.


## Why should I care?

`us` enables you to do a number of cool things with Sia that were previously
infeasible, difficult, or inefficient. You can specify exactly which hosts you
want to use. You can collect data on exactly how much you paid to download a
file, and exactly how long it took the host to transfer it to you. You can use
this information to manually blacklist hosts, selecting only the cheapest or
fastest hosts when downloading. You can "pack" multiple files into a single
uploaded sector: if you're uploading an album of JPEGs averaging 250 KB each,
this reduces storage and bandwidth costs by about 16x. You can download one of
those JPEGs without downloading the full sector, too. You can trivially share
files, just by sending the metadata to a friend. You can stream files over
HTTP or mount a virtual Sia filesystem with FUSE, enjoying low latency as a
result of partial downloads. You can upload and download without needing to
run a full consensus node. And most importantly, you can build apps that
leverage Sia to store and serve content.

Here are some ideas for apps you could build with `us`:

- A storage backend for [go-cloud](https://github.com/google/go-cloud), [upspin](https://github.com/upspin/upspin), or [minio](https://github.com/minio/minio)
- A site where you can buy contracts directly, paying with BTC (via [LN](https://lightning.network/)?) instead of SC
- A cron job that downloads 1 KB from a host every 24 hours and reports various metrics (latency, bandwidth, price)
- A site that aggregates host metrics to provide a centralized host database
- A gateway that serves static websites stored on Sia
- A mobile app that stores and retrieves files stored on Sia


## What do I need to get started?

Run `go get github.com/lukechampine/us/...` to install `us` and its
dependencies. For subsequent builds, run `make`. No pre-built binaries
are provided at this time.

If you want to use `us` to manage your contracts and files manually, you're
looking for `user`, a CLI tool that provides convenient access to `us`
functionality. A usage guide is available [here](cmd/user/README.md).

If you want to use `us` to build apps, please read [DEVELOPERS.md](DEVELOPERS.md).

If you would like to contribute (thank you!), please read [CONTRIBUTING.md](CONTRIBUTING.md).


## What else do I need to know?

`user` demands much more work on behalf of the user than `siad`. You are
responsible for choosing good hosts to form contracts with, and for migrating
file data to new hosts if the old hosts flake out. **Failure to perform these
duties can result in loss of data.**

Please be aware that `us` is in an experimental, unstable state. `us`
contracts and files differ from the corresponding `siad` formats, so you
should **not** assume that contracts formed and files uploaded using `us` are
transferable to `siad`, nor vice versa. Until `us` is marked as stable,
**don't spend any siacoins on `us` that you can't afford to lose.**

