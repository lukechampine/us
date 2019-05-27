us
==

[![GoDoc](https://godoc.org/lukechampine.com/us?status.svg)](https://godoc.org/lukechampine.com/us)
[![Go Report Card](https://goreportcard.com/badge/lukechampine.com/us)](https://goreportcard.com/report/lukechampine.com/us)

`us` is an alternative interface to the [Sia](https://gitlab.com/NebulousLabs/Sia)
network. It provides low-level, developer-oriented APIs and formats that
facilitate the storage and retrieval of files on Sia.

"Low-level" means that `us` generally avoids making decisions on behalf of the
user. For example, when renting storage, the user must decide which hosts to
form contracts with, how many coins to spend on each contract, when to renew
contracts, when to migrate data to new hosts, etc. These questions do not have
simple answers; they vary according to the context and goals of the user.
Recognizing this, the `us` philosophy is to provide the user with a set of
building blocks rather than a one-size-fits-all solution.


## Why should I care?

The `us` project is at the forefront of Sia research and development, exploring
new ideas, tools, and protocols that complement and extend the existing
ecosystem. With `us`, you can do things currently not supported by `siad`, such
as:

- Specify exactly which hosts you want to use
- Share you files and/or contracts with a friend
- Upload your meme folder without padding each file to 4 MiB
- Mount a virtual Sia filesystem with FUSE
- Upload and download without running a Sia full node

More importantly, you can use `us` to build apps on Sia. Here are a few ideas:

- A storage backend for [go-cloud](https://github.com/google/go-cloud), [upspin](https://github.com/upspin/upspin), or [minio](https://github.com/minio/minio)
- A site where you can buy contracts directly, paying with BTC (via [LN](https://lightning.network/)?) instead of SC
- A cron job that downloads 1 KB from a host every 24 hours and reports various metrics (latency, bandwidth, price)
- A site that aggregates host metrics to provide a centralized host database ([done!](https://siastats.info/hosts))
- A mobile app that stores and retrieves files stored on Sia


## What do I need to get started?

If you're a renter, you're probably looking for [`user`](https://github.com/lukechampine/user),
a CLI tool for forming contracts and transferring files that leverages the `us` renter packages.

If you're a hodler or an exchange, you're probably looking for [`walrus`](https://github.com/lukechampine/walrus),
a high-performance Sia wallet server that leverages the `us` wallet packages.

If you're a developer who wants to build something with `us`, please get it
touch with me via [email](mailto:luke@lukechampine.com),
[reddit](https://reddit.com/u/lukechampine), or
[Discord](https://discord.gg/sia) (@nemo).

If you would like to contribute (thank you!), please read [CONTRIBUTING.md](CONTRIBUTING.md).

Please be aware that `us` is in an experimental, unstable state. `us`
contracts and files differ from the corresponding `siad` formats, so you
should **not** assume that contracts formed and files uploaded using `us` are
transferable to `siad`, nor vice versa. Until `us` is marked as stable,
**don't spend any siacoins on `us` that you can't afford to lose.**

