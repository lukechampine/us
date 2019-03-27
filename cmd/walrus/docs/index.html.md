---
title: walrus API Reference

language_tabs:
  - shell: curl

search: true
---

# Introduction

This page describes the `walrus` HTTP API. `walrus` is a seed-based wallet that
can be used as a traditional hot wallet or as part of a cold wallet/watch-only
wallet setup. Like the rest of the `us` project, `walrus` presents a low-level
interface and is targeted towards developers, not end-users. The goal is to
provide a flexible, performant API that is suitable for exchanges, web wallets,
and other applications that require precise control of their siacoins.


# Authentication

The `walrus` API is currently unauthenticated.


# Generic Wallet API

`walrus` can be run as a hot wallet or as a watch-only wallet. The following
routes are available in either mode.

## List Addresses

> Example Request:

```shell
curl "localhost:9380/addresses"
```

> Example Response:

```json
[
  "e506d7f1c03f40554a6b15da48684b96a3661be1b5c5380cd46d8a9efee8b6ffb12d771abe9f",
  "5ac6af95fe284b4bbb0110ef51d3c90f3e9ea37586352ec83bad569230bad7f37a452c0a2a2f"
]
```

Lists all addresses known to the wallet.

### HTTP Request

`GET http://localhost:9380/addresses`

### Errors

None


## Get Address Info

> Example Request:

```shell
curl "localhost:9380/addresses/5ac6af95fe284b4bbb0110ef51d3c90f3e9ea37586352ec83bad569230bad7f37a452c0a2a2f"
```

> Example Response:

```json
{
  "unlockConditions": {
    "publicKeys": [
      "ed25519:0ea4e46899fe246e14122e3ca5865a7006d99086c52b1c63ab0e32226e56a7a1"
    ],
    "signaturesRequired": 1
  },
  "keyIndex": 1
}
```

Returns information about a specific address, including its unlock conditions
and the index it was derived from.

### HTTP Request

`GET http://localhost:9380/addresses/<addr>`

### URL Parameters

Parameter | Description
----------|------------
   addr   | The address to query

### Errors

  Code | Description
-------|------------
  400  | Address is invalid
  404  | Address does not belong to the wallet


## Get the Current Balance

> Example Request:

```shell
curl "localhost:9380/balance"
```

> Example Response:

```json
"123000000000000000000000000000"
```

Returns the current wallet balance in hastings. This is equivalent to summing
the values of the outputs returned by [`/utxos`](#list-unspent-outputs).

### HTTP Request

`GET http://localhost:9380/balance`

### Errors

None


## Broadcast a Transaction Set

> Example Request:

```shell
curl "localhost:9380/broadcast" \
  -X POST \
  -d '[{
    "siacoinInputs": [{
      "parentID": "b8c63a8f435bfff7bf8c1f6c7ece0066599fa4e08cb74ab5929e84b014e408c8",
      "unlockConditions": {
        "publicKeys": [ "ed25519:8408ad8d5e7f605995bdf9ab13e5c0d84fbe1fc610c141e0578c7d26d5cfee75" ],
        "signaturesRequired": 1
      }
    }],
    "siacoinOutputs": [{
      "value": "100000000000000000000000000000",
      "unlockHash": "df1b42c80b5f7a67331893fde0923a5071d6d7dff4c78baec547cf5ca4d314a1d78b6b1c8d42"
    }],
    "minerFees": [ "13000000000000000000000000000" ],
    "transactionSignatures": [{
      "parentID": "b8c63a8f435bfff7bf8c1f6c7ece0066599fa4e08cb74ab5929e84b014e408c8",
      "publicKeyIndex": 0,
      "coveredFields": { "wholeTransaction": true },
      "signature": "rFtBFv9oeScpO3mhp6O2liMwBKYXn05SaOmzhhjQtIkOwAClaJTpLEKn3U26zYis2AG2tH2idWSJNZXNSVa8DQ=="
    }]
  }]'
```

Broadcasts the supplied transaction set to all connected peers.

<aside class="notice">
Most transaction sets contain a single transaction. A "parent" transaction is
only necessary if the "child" transaction spends outputs created in the parent,
and the parent is not already in the blockchain.
</aside>

### HTTP Request

`POST http://localhost:9380/broadcast`

### Errors

  Code | Description
-------|------------
  400  | Transaction set is invalid


## Get Consensus Info

> Example Request:

```shell
curl "localhost:9380/consensus"
```

> Example Response:

```json
{
  "height": 1368,
  "ccid": "ffdb020d509773476617e5805923f81025bbf7b77d4a1691489cfc574b0b3b61"
}
```

Returns the current blockchain height and consensus change ID. The latter is a
unique ID that changes whenever blocks are added to the blockchain.

<aside class="notice">
Clients may wish to poll this route to monitor the blockchain for new
transactions. Since the blockchain can be reorged without the height changing,
clients should always poll the consensus change ID for changes, not the height.
</aside>

### HTTP Request

`GET http://localhost:9380/consensus`

### Errors

None


## Get Recommended Transaction Fee

> Example Request:

```shell
curl "localhost:9380/fee"
```

> Example Response:

```json
"123000000000"
```

Returns the current recommended transaction fee in hastings per byte of the
Sia-encoded transaction.

<aside class="notice">
This value is the median fee of the last six blocks. Using a higher fee may
result in your transaction being confirmed faster.
</aside>

<aside class="notice">
You can approximate the size of a standard Sia-encoded transaction with the
following equation:<br>
<br>
<code>size = 100 + (num_inputs * 313) + (num_outputs * 50)</code><br>
<br>
Do not use this equation for transactions that include arbitrary data, file
contracts, storage proofs, siafunds, or multi-sig inputs.
</aside>

### HTTP Request

`GET http://localhost:9380/consensus`

### Errors

None


## List Limbo Outputs

> Example Request:

```shell
curl "localhost:9380/limbo"
```

> Example Response:

```json
[
	{
		"ID": "b8c63a8f435bfff7bf8c1f6c7ece0066599fa4e08cb74ab5929e84b014e408c8",
		"value": "123000000000000000000000000000",
		"unlockHash": "e506d7f1c03f40554a6b15da48684b96a3661be1b5c5380cd46d8a9efee8b6ffb12d771abe9f",
		"limboSince": "2019-02-22T23:25:11-05:00"
	}
]
```

Lists outputs that are in [Limbo](#limbo).

### HTTP Request

`GET http://localhost:9380/limbo`

### Errors

None


## Move an Output to Limbo

> Example Request:

```shell
curl "localhost:9380/limbo/8d16e3de006a57028fd014ab85c2a76a32c5bbd2e1df9340b04795734c9c3372" \
  -X PUT
```

Places an output in [Limbo](#limbo). The output will no longer appear in
[`/utxos`](#list-unspent-outputs) or contribute to the wallet's balance.

<aside class="notice">
Manually moving outputs to Limbo is typically unnecessary. When a transaction is
broadcast, its outputs are moved to Limbo automatically.
</aside>

### HTTP Request

`PUT http://localhost:9380/limbo/<id>`

### URL Parameters

Parameter | Description
----------|------------
    id    | The ID of the output to move

### Errors

  Code | Description
-------|------------
  400  | ID is invalid


## Remove an Output from Limbo

> Example Request:

```shell
curl "localhost:9380/limbo/8d16e3de006a57028fd014ab85c2a76a32c5bbd2e1df9340b04795734c9c3372" \
  -X DELETE
```

Removes an output from [Limbo](#limbo). The output will appear in
[`/utxos`](#list-unspent-outputs) and contribute to the wallet's balance.

<aside class="notice">
If an output appears in the blockchain, it will automatically be removed from
Limbo, but (because it has been spent) it will not appear in <code>/utxos</code>
or contribute to the wallet's balance.
</aside>

### HTTP Request

`DELETE http://localhost:9380/limbo/<id>`

### URL Parameters

Parameter | Description
----------|------------
    id    | The ID of the output to remove

### Errors

  Code | Description
-------|------------
  400  | ID is invalid


## Add a Transaction Memo

> Example Request:

```shell
curl "localhost:9380/memos/2936d6eab2272dda76603aa8078be02d979cf52ac3d06c799536c725e32686ba" \
  -X PUT
  -d 'My example memo'
```

Adds a memo for a transaction, overwriting the previous memo if it exists.

<aside class="warning">
Memos are not stored on the blockchain! They exist only in your local wallet.
</aside>

### HTTP Request

`PUT http://localhost:9380/memos/<txid>`

### URL Parameters

Parameter | Description
----------|------------
   txid   | The ID of the transaction

### Errors

  Code | Description
-------|------------
  400  | Transaction ID is invalid


## Get a Transaction Memo

> Example Request:

```shell
curl "localhost:9380/memos/2936d6eab2272dda76603aa8078be02d979cf52ac3d06c799536c725e32686ba"
```

> Response body:

```
My example memo
```

Retrieves the memo for a transaction.

### HTTP Request

`GET http://localhost:9380/memos/<txid>`

### URL Parameters

Parameter | Description
----------|------------
   txid   | The ID of the transaction

### Errors

  Code | Description
-------|------------
  400  | Transaction ID is invalid


## List Transactions

> Example Request:

```shell
curl "localhost:9380/transactions"
```

> Example Response:

```json
[
  "2936d6eab2272dda76603aa8078be02d979cf52ac3d06c799536c725e32686ba",
  "355e6839329ff8cbc658d0b661a938c1988d0addce6b935b0d56c074cc3532bf",
  "3d9d51c636a736587b77a9e88d901d12acd0d49fbf92d27c8f8379f1510596bf",
  "e77cae8edef455685f792483b864b6489dec74284b91a380cb3221365c239ca9",
  "7e3f8ccc2d8b559fca057ebe5be4dfae99b7c9fcd4693c3c1b8e70894536c52a"
]
```

> To retrieve just the three most recent transactions:

```shell
curl "localhost:9380/transactions?max=3"
```

> Example Response:

```json
[
  "2936d6eab2272dda76603aa8078be02d979cf52ac3d06c799536c725e32686ba",
  "355e6839329ff8cbc658d0b661a938c1988d0addce6b935b0d56c074cc3532bf",
  "3d9d51c636a736587b77a9e88d901d12acd0d49fbf92d27c8f8379f1510596bf",
]
```

> To limit the results to transactions relevant to a given address:

```shell
curl "localhost:9380/transactions?addr=e506d7f1c03f40554a6b15da48684b96a3661be1b5c5380cd46d8a9efee8b6ffb12d771abe9f"
```

> Example Response:

```json
[
  "2936d6eab2272dda76603aa8078be02d979cf52ac3d06c799536c725e32686ba",
  "3d9d51c636a736587b77a9e88d901d12acd0d49fbf92d27c8f8379f1510596bf",
  "e77cae8edef455685f792483b864b6489dec74284b91a380cb3221365c239ca9",
  "7e3f8ccc2d8b559fca057ebe5be4dfae99b7c9fcd4693c3c1b8e70894536c52a"
]
```

Lists the IDs of transactions relevant to the wallet. The IDs are ordered
newest-to-oldest.

### HTTP Request

`GET http://localhost:9380/transactions?addr=<addr>&max=<max>`

### URL Parameters

Parameter | Description
----------|------------
   addr   | Return only transactions relevant to this address
    max   | The maximum number of transactions to return

### Errors

  Code | Description
-------|------------
  400  | Invalid address or maximum


## Get Transaction Info

> Example Request:

```shell
curl "localhost:9380/transactions/2936d6eab2272dda76603aa8078be02d979cf52ac3d06c799536c725e32686ba"
```

> Example Response:

```json
{
  "transaction": {
    "siacoinInputs": [{
      "parentID": "b87491287c34880a1b512f47ec932d777c6809672236e2533fd565969e69a09b",
      "unlockConditions": {
        "publicKeys": [ "ed25519:37e32b4a07d5a617c8b872daabcba320d604f3c5017c580956c1ac42c37f8059" ],
        "signaturesRequired": 1
      }
    }],
    "siacoinOutputs": [{
      "value": "123000000000000000000000000000",
      "unlockHash": "e506d7f1c03f40554a6b15da48684b96a3661be1b5c5380cd46d8a9efee8b6ffb12d771abe9f"
    }],
    "minerFees": [ "22500000000000000000000" ],
    "transactionSignatures": [{
      "parentID": "b87491287c34880a1b512f47ec932d777c6809672236e2533fd565969e69a09b",
      "publicKeyIndex": 0,
      "coveredFields": { "wholeTransaction": true },
      "signature": "WbJO3jeLBgzbMZI7D4yx5dNrX5Qw2e3/8lTakL/F23e3DL0nG2O02zUmdlq9466lx9uhfT3ejJOsO1oB3lMZBQ=="
    }]
  },
  "inflow": "123000000000000000000000000000",
  "outflow": "22500000000000000000000",
  "feePerByte": "48491379310344827586"
}
```

Returns the transaction with the specified ID, as well as inflow, outflow, and
fee information. The transaction must appear in [`/transactions`](#list-transactions).

### HTTP Request

`GET http://localhost:9380/transactions/<txid>`

### URL Parameters

Parameter | Description
----------|------------
   txid   | The ID of the transaction to retrieve

### Errors

  Code | Description
-------|------------
  400  | Invalid transaction ID
  404  | Unknown transaction


## List Unspent Outputs

> Example Request:

```shell
curl "localhost:9380/utxos"
```

> Example Response:

```json
[
  {
    "ID": "8d16e3de006a57028fd014ab85c2a76a32c5bbd2e1df9340b04795734c9c3372",
    "value": "10000000000000000000000000000",
    "unlockConditions": {
      "publicKeys": [ "ed25519:0ea4e46899fe246e14122e3ca5865a7006d99086c52b1c63ab0e32226e56a7a1" ],
      "signaturesRequired": 1
    },
    "unlockHash": "5ac6af95fe284b4bbb0110ef51d3c90f3e9ea37586352ec83bad569230bad7f37a452c0a2a2f"
  },
  {
    "ID": "d8412f884e85519a6896cac505b4eceafd16ed79ca5d2d44e0b24a80a9df8083",
    "value": "123000000000000000000000000000",
    "unlockConditions": {
      "publicKeys": [ "ed25519:8408ad8d5e7f605995bdf9ab13e5c0d84fbe1fc610c141e0578c7d26d5cfee75" ],
      "signaturesRequired": 1
    },
    "unlockHash": "e506d7f1c03f40554a6b15da48684b96a3661be1b5c5380cd46d8a9efee8b6ffb12d771abe9f"
  }
]
```

Returns the outputs that the wallet can spend.

### HTTP Request

`GET http://localhost:9380/utxos`

### Errors

None


# Hot Wallet API

Hot wallets have all of the routes of [generic wallets](#generic-wallet-api),
but are also capable of generating new addresses and signing transactions.

## Generate a New Address

> Example Request:

```shell
curl "localhost:9380/nextaddress" \
  -X POST
```

> Example Response:

```json
"cfb5d86e10e55810187abd06ca5463f267b60d463fc6af104f7b0f5623248e104fe3b4fb0d5e"
```

Generates a new address from the wallet's seed. The address will also appear in
[`/addresses`](#list-addresses).

<aside class="notice">
Generating a new address increments the seed index.
</aside>

### HTTP Request

`POST http://localhost:9380/nextaddress`

### Errors

None


## Get the Current Seed Index

> Example Request:

```shell
curl "localhost:9380/seedindex"
```

> Example Response:

```json
3
```

Returns the wallet's current seed index. This index will be used to derive the
next address. It is equal to the number of addresses reported by
[`/addresses`](#list-addresses).

### HTTP Request

`GET http://localhost:9380/seedindex`

### Errors

None


## Sign a Transaction

> Example Request:

```shell
curl "localhost:9380/sign" \
  -X POST \
  -d '{
    "transaction": {
      "siacoinInputs": [{
        "parentID": "b8c63a8f435bfff7bf8c1f6c7ece0066599fa4e08cb74ab5929e84b014e408c8",
        "unlockConditions": {
          "publicKeys": [ "ed25519:8408ad8d5e7f605995bdf9ab13e5c0d84fbe1fc610c141e0578c7d26d5cfee75" ],
          "signaturesRequired": 1
        }
      }],
      "siacoinOutputs": [{
        "value": "100000000000000000000000000000",
        "unlockHash": "df1b42c80b5f7a67331893fde0923a5071d6d7dff4c78baec547cf5ca4d314a1d78b6b1c8d42"
      }],
      "minerFees": [ "13000000000000000000000000000" ]
    }
  }'
```

> By default, the wallet will add a transaction signature for every input it
> controls. Alternatively, you may use `toSign` to specify which signatures to
> fill in:

```shell
curl "localhost:9380/sign" \
  -X POST \
  -d '{
    "transaction": {
      "siacoinInputs": [{
        "parentID": "b8c63a8f435bfff7bf8c1f6c7ece0066599fa4e08cb74ab5929e84b014e408c8",
        "unlockConditions": {
          "publicKeys": [ "ed25519:8408ad8d5e7f605995bdf9ab13e5c0d84fbe1fc610c141e0578c7d26d5cfee75" ],
          "signaturesRequired": 1
        }
      }],
      "siacoinOutputs": [{
        "value": "100000000000000000000000000000",
        "unlockHash": "df1b42c80b5f7a67331893fde0923a5071d6d7dff4c78baec547cf5ca4d314a1d78b6b1c8d42"
      }],
      "minerFees": [ "13000000000000000000000000000" ],
      "transactionSignatures": [{
        "parentID": "b8c63a8f435bfff7bf8c1f6c7ece0066599fa4e08cb74ab5929e84b014e408c8",
        "publicKeyIndex": 0,
        "coveredFields": { "wholeTransaction": true },
      }]
    },
    "toSign": [ 0 ]
  }'
```

> Example Response:

```json
{
  "siacoinInputs": [{
    "parentID": "b8c63a8f435bfff7bf8c1f6c7ece0066599fa4e08cb74ab5929e84b014e408c8",
    "unlockConditions": {
      "publicKeys": [ "ed25519:8408ad8d5e7f605995bdf9ab13e5c0d84fbe1fc610c141e0578c7d26d5cfee75" ],
      "signaturesRequired": 1
    }
  }],
  "siacoinOutputs": [{
    "value": "100000000000000000000000000000",
    "unlockHash": "df1b42c80b5f7a67331893fde0923a5071d6d7dff4c78baec547cf5ca4d314a1d78b6b1c8d42"
  }],
  "minerFees": [ "13000000000000000000000000000" ],
  "transactionSignatures": [{
    "parentID": "b8c63a8f435bfff7bf8c1f6c7ece0066599fa4e08cb74ab5929e84b014e408c8",
    "publicKeyIndex": 0,
    "coveredFields": { "wholeTransaction": true },
    "signature": "rFtBFv9oeScpO3mhp6O2liMwBKYXn05SaOmzhhjQtIkOwAClaJTpLEKn3U26zYis2AG2tH2idWSJNZXNSVa8DQ=="
  }]
}
```

Signs the supplied transaction using keys derived from the wallet's seed.

### HTTP Request

`POST http://localhost:9380/sign`

### Errors

  Code | Description
-------|------------
  400  | Transaction is invalid or wallet does not possess signing key


# Watch-Only Wallet API

Watch-only wallets have all of the routes of [generic wallets](#generic-wallet-api),
as well as the ability to track arbitrary addresses. Unlike hot wallets,
watch-only wallets cannot generate new addresses or sign transactions.

## Import an Address

> Example Request:

```shell
curl "localhost:9380/addresses" \
  -X POST \
  -d '{
    "unlockConditions": {
        "publicKeys": [ "ed25519:fa48a995dc17f978916d334afb0a28d04215a40fddc33db10d8a17b2ca93f6d4" ],
        "signaturesRequired": 1
    },
    "keyIndex": 1
  }'
```

> Example Response:

```json
"8066f825fd680559acba2c14ca7e8b0f4aa5e8a1eece3908485953d6a2e8ce3b991322eaf7d1"
```

Adds a set of unlock conditions to the wallet, returning the corresponding
address. Future transactions and outputs relevant to this address will be
recorded.

<aside class="warning">
Importing an address does NOT import transactions and outputs relevant to that
address that are already in the blockchain. To accomplish this, you must rescan
the blockchain.
</aside>

### HTTP Request

`POST http://localhost:9380/addresses`

### Errors

  Code | Description
-------|------------
  400  | Invalid unlock conditions or key index


## Remove an Address

> Example Request:

```shell
curl "localhost:9380/addresses/8066f825fd680559acba2c14ca7e8b0f4aa5e8a1eece3908485953d6a2e8ce3b991322eaf7d1" \
  -X DELETE
```

Removes an address from the wallet. Future transactions and outputs relevant to
this address will not be recorded.

<aside class="warning">
Removing an address does NOT remove transactions and outputs relevant to that
address that are already recorded in the wallet. To accomplish this, you must
rescan the blockchain.
</aside>

### HTTP Request

`DELETE http://localhost:9380/addresses/<addr>`

### URL Parameters

Parameter | Description
----------|------------
   addr   | The address to remove

### Errors

  Code | Description
-------|------------
  400  | Invalid address


# Limbo

When an output is spent in a transaction, it cannot be spent again. However,
there is a period of uncertainty between the transaction being *broadcast* to
miners and the transaction actually appearing in the blockchain. If the
transaction has insufficient fees, or is invalidated by a later block, miners
may discard it.

During this period of uncertainty, we say that the transaction's outputs are "in
Limbo." After an output has been in Limbo for a sufficiently long time, it is
typically safe to assume that its corresponding transaction will never be
included in a future block. The output may then be manually removed from Limbo
and reused in a different transaction without risking a double-spend.

<aside class="warning">
Limbo is distinct from the question of transaction finality. Outputs will be
removed from Limbo as soon as they have a single confirmation, but subsequent
blocks may reorg the chain and "unspend" the output. Limbo should be used solely
as a means to avoid accidental double-spends.
</aside>


# Transaction Structure

```json
{
  "siacoinInputs": [
    {
      "parentID": "b8c63a8f435bfff7bf8c1f6c7ece0066599fa4e08cb74ab5929e84b014e408c8",
      "unlockConditions": {
        "publicKeys": [ "ed25519:8408ad8d5e7f605995bdf9ab13e5c0d84fbe1fc610c141e0578c7d26d5cfee75" ],
        "signaturesRequired": 1
      }
    }
  ],
  "siacoinOutputs": [
    {
      "value": "10000000000000000000000000000",
      "unlockHash": "5ac6af95fe284b4bbb0110ef51d3c90f3e9ea37586352ec83bad569230bad7f37a452c0a2a2f"
    },
    {
      "value": "100000000000000000000000000000",
      "unlockHash": "df1b42c80b5f7a67331893fde0923a5071d6d7dff4c78baec547cf5ca4d314a1d78b6b1c8d42"
    }
  ],
  "minerFees": [ "13000000000000000000000000000" ],
  "transactionSignatures": [
    {
      "parentID": "b8c63a8f435bfff7bf8c1f6c7ece0066599fa4e08cb74ab5929e84b014e408c8",
      "publicKeyIndex": 0,
      "coveredFields": { "wholeTransaction": true },
      "signature": "rFtBFv9oeScpO3mhp6O2liMwBKYXn05SaOmzhhjQtIkOwAClaJTpLEKn3U26zYis2AG2tH2idWSJNZXNSVa8DQ=="
    }
  ]
}
```

A typical transaction can be seen to the right. A brief overview of each field
follows.

First are the `siacoinInputs`. Each input spends an output created by a previous
transaction. The `parentID` identifies which output is being spent, and the
`unlockConditions` reveal the preimage of the unlock hash (also known as an
address). Unlock conditions consist of a set of `publicKeys`, a number of
`signaturesRequired`, and a `timelock`. The vast majority of unlock conditions
use a single public key and no timelock (i.e. a timelock of 0); these are known
as "standard unlock conditions." The addresses returned by
[`/nextaddress`](#generate-a-new-address) always have standard unlock
conditions.

Next come the `siacoinOutputs`. Each output specifies an `unlockHash` (address)
and a `value` of coins to send to that address. When these outputs are later
spent, the `unlockConditions` revealed in the input must hash to the
`unlockHash` specified in the output.

<aside class="notice">
Values are specified in hastings, where 10^24 hastings = 1 siacoin. You must use
an arbitrary-precision integer library to perform arithmetic on hastings.
</aside>

Next are the `minerFees`. Unlike Bitcoin, the fees are specified explicitly: the
sum of the inputs must equal the sum of the outputs plus the miner fees.

Finally come the `transactionSignatures`. Every input must have a corresponding
signature. The `parentID` specifies which input is being signed, and the
`publicKeyIndex` identifies which of the `publicKeys` in the input is being used
to sign. The `coveredFields` indicate what transaction data is being signed;
except for certain special cases (such as file contract revisions), it should
always specify that the `wholeTransaction` is being signed. And of course, every
transaction signature must include the actual cryptographic `signature`.
