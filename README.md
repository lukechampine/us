us
==

[![GoDoc](https://godoc.org/github.com/lukechampine/us?status.svg)](https://godoc.org/github.com/lukechampine/us)
[![Go Report Card](https://goreportcard.com/badge/github.com/lukechampine/us)](https://goreportcard.com/report/github.com/lukechampine/us)

`us` is an alternative interface to the [Sia](http://github.com/NebulousLabs/Sia)
network. It provides low-level, developer-oriented APIs and formats that
facilitate the storage and retrieval of files on the Sia network. "Low-level"
means that `us` provides minimal, layered abstractions, and avoids making
decisions on behalf of the user. For example, when renting storage, the user
must decide which hosts to form contracts with, how many coins to spend on
each contract, when to renew contracts, when to migrate data to new hosts,
etc. These questions do not have simple answers; they vary according to the
context and goals of the user. Recognizing this, the `us` philosophy is to
provide the user with a set of building blocks rather than a one-size-fits-all
solution.

Currently, the main focus of the `us` project is to apply these concepts to
the Sia renter. To this end, it provides a CLI tool called `user` that
leverages `us` packages to create a simple user interface for making contracts
and storing and retrieving files. The full guide for using `user` can be found
[here](cmd/user/README.md).

It is strongly recommended that you read [`us` from the ground up](ground.md)
guide before using `user` or writing software that leverages `us` packages. This
guide introduces the components of the `us` project and explains the rationale
behind their design. The components are simple, but together they form a
powerful and expressive system. Understanding each of the components and their
design tradeoffs will make it easier to use, maintain, and extend all aspects
of the `us` system.

`us` is fully compatible with Sia's network protocols and consensus code.
However, none of the `us` APIs are bound by Sia's 1.0 API compatibility
promise; they are subject to change at any time. Developers should use caution
when writing code that relies on such APIs until they are explicitly marked as
stable.

---

Three things to know about `us`:

1. `us` has many exciting features. It supports small files: you can "pack"
multiple files into a single uploaded sector, and download them individually.
File-sharing is supported out of the box: just send the metadata file to a
friend, and as long as they have contracts with the right hosts, they can
download the file. You can also stream files over HTTP and mount a virtual Sia
filesystem with FUSE.

2. `us` demands much more work on behalf of the user than `siad`. You are
responsible for choosing good hosts to form contracts with, and for migrating
file data to new hosts if the old hosts flake out. The good news is that this
work can be automated with custom scripts.

3. `us` is experimental, and sacrifices compatibility for the sake of cleaner
code and faster development. Its formats differ from the `siad` formats, so
you should **not** assume that contracts formed and files uploaded using `us`
are transferable to `siad`, nor vice versa. No part of `us` is currently
marked as stable; until that changes, **don't spend any siacoins on `us` that
you can't afford to lose.**
