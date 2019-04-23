# walrus

`walrus` is a wallet server that can be used as a traditional hot wallet or as
part of a cold wallet/watch-only wallet setup. Like the rest of the `us`
project, `walrus` presents a low-level interface and is targeted towards
developers, not end-users. The goal is to provide a flexible, performant API
that is suitable for exchanges, web wallets, and other applications that require
precise control of their siacoins.

API docs for the server are available [here](https://lukechampine.com/walrus).

## Usage

To start the server in watch-only mode, run `walrus start --watch-only`. You may
then use the watch-only API routes.

To start the server in hot wallet mode, first you'll need to generate a seed
with `walrus seed`. (Don't be alarmed: `walrus` seeds are only 15 words long.)
Then start the server with `walrus start` and enter your seed at the prompt. You
can bypass the prompt by storing your seed in the `WALRUS_SEED` environment
variable. You may then use the hot wallet API routes.

A client for the `walrus` API is available [here](https://github.com/lukechampine/walrus-cli).
