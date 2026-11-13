# Release Notes

## Latest changes

## 0.8.0

One async-native client, usable from sync code through `universalasync`. `AsyncTron` and the other `Async*` names remain as aliases for compatibility, but aren't recommended: drop the prefix. See the [migration notes](https://tronpy.bitcart.ai/async/#migrating-to-the-single-client)

**Breaking**: `requests` is removed. Sync users catch `httpx2` exceptions, `HTTPProvider.sess` is gone, TLS uses the OS trust store and redirects are no longer followed

**Breaking**: `asyncio.run(client.method())` raises `ValueError` (`TypeError` on Python 3.14+) after the call has already run, so `asyncio.run(tx.broadcast())` sends and then raises. Wrap it in `async def main()`

**Breaking**: sync-style calls inside a running event loop return a coroutine

**Breaking**: type checkers see the methods as async, so typed sync callers need `cast` or `type: ignore`

**Breaking**: custom providers need an async `make_request`

**Breaking**: `Transaction(raw, client=c)` no longer makes a network call, use `Transaction.create`. `tronpy.tron.EMPTY` is removed

**Breaking**: `HTTPProvider` arguments after `timeout` are keyword-only

**Breaking**: `AsyncTron` users now get `ValueError` when passing `conf={"timeout": ...}` along with a provider

`HTTPProvider` keeps one client per event loop, so `Tron` works across threads, repeated `asyncio.run`

Add `HTTPProvider(client_factory=...)` to use custom HTTP client settings on every event loop. A client passed with `client=` only applies to the event loop current when the provider is created

Fix `broadcast` raising `KeyError` in async code after sending, when a node omits `txid`

**Breaking**: the async client now uses `httpx2` instead of `httpx`. Build `AsyncHTTPProvider(client=...)` clients and catch timeouts and other HTTP errors from `httpx2`. TLS verification now uses the OS trust store instead of `certifi`

**Breaking**: `Tron` and `AsyncTron` now raise `ValueError` on an unknown `network`, instead of silently connecting to mainnet or to `TRONPY_HTTP_PROVIDER_URI`

Move `as_shielded_trc20` from `ContractMethod`, where it always raised `TypeError`, to `Contract`

Fix `AsyncTron.get_contract_as_shielded_trc20` returning the sync wrapper, and `AsyncShieldedTRC20` failing on `mint`, `transfer` and `burn`, or on a second read of `trc20` or `scale_factor`

`Tron.get_asset` now raises `ValueError` when given both an id and an issuer, instead of returning the exception

`is_note_spent` now returns `False` instead of `None` when the node omits `is_spent`

Calling contract methods or printing them no longer raises `AttributeError` when their ABI has no `stateMutability`

Broadcasting or updating a transaction without a client now raises a clear `TypeError` instead of `AttributeError`

Signing a transaction that has no client and no known permission no longer raises `TypeError`

Report the actual number of arguments when contract methods and constructors get a wrong number of keyword arguments

`BaseKey` is now abstract. It could already only be built without arguments, and the result had no key data

Annotate the whole package, check it with mypy in CI, and ship a `py.typed` marker so type checkers use these annotations

## 0.7.0

**Breaking**: Drop support for python 3.9 and 3.10

**Breaking**: Remove `PrivateKey.from_passphrase` and `get_address_from_passphrase`. They used a single SHA-256 of the passphrase as the private key, which is crackable offline, and existed for compatibility with `wallet/createaddress`, removed from java-tron in 4.7.1.1. Use `generate_address` or a mnemonic instead

**Breaking**: Remove the `sha256` helper from `tronpy.keys`, use `hashlib.sha256` instead

`PrivateKey.fromhex` and `PublicKey.fromhex` are now typed to return their own class instead of `BaseKey`

Fix encoding and decoding of the `trcToken` ABI type

Add support for python 3.15

Use `cryptography` instead of `coincurve` for secp256k1 operations

Allow `eth-abi` 6 and `pycryptodome` 4

Upgrade the `mnemonic` extra to 0.21

Add `raw_data_hex` to transactions and their `to_json` output, including offline-built ones, so they can be signed by tools that require it, like TronWeb

If you pass `to_json` output to `trontxsize`, upgrade it to 1.5.0 or newer

Fix wrong `txID` of offline-built transactions with a memo or `permission_id`

Fix `Transaction.from_json` and `AsyncTransaction.from_json` failing on JSON strings

Fix `from tronpy.providers import *`

Move docs to Zensical and CI to GitHub Actions

## 0.6.2

Add support for python 3.14

## 0.6.1

Allow to parse not fully valid ABI data with `strict=False` in `trx_abi.decode_abi`

## 0.6.0

Drop support for python 3.8, add support for python 3.13

Experimental offline transaction creation: install tronpy with `offline` extra, and then pass `offline=True` and `ref_block_id` to `.build()` method

New `get_energy` method added

Use ruff for linting and formatting

Switch to hatchling instead of poetry for package building

Make `Signature` class tronweb-compatible: it can now correctly parse those signatures, and there's a method `tronweb_hash` on signature to return signature exactly like tronweb. Note that e.g. `sign_msg` etc that receive non-hash data now uses `keccak256` (with the tron message header) instead of `sha256` as it should be in tron. Both `keccak256` and `sha256` are now exported, as well as `hash_message`

Add `getcandelegatedmaxsize`

Fix infinite recursion in handling of api keys for trongrid

Port trongrid logic to async http client

## 0.5.0

Python 3.12 support, drop python 3.7 support

Use cryptographically secure generator for `PrivateKey`s

Upgrade dependencies

A few new methods related to stake V2 API

## 0.4.0

**Breaking**: Support stake V2 APIs (note: old APIs won't work anymore)

Add optional ability to derive addresses from seed

Use correct version in User-Agent

Trongrid JWT support

Separate `trigger_constant_contract` from `trigger_const_smart_contract_function` method

## 0.3.0

Update dependencies, remove upper version pins

Switch to native cryptography for secp256k1 curves via coincurve library, no longer use pure-python ecdsa library

Use poetry-core in pyproject.toml for lighter builds

Fix padding bytes issues

Make latest block id parsing more reliable

New `get_function_by_selector` function

Fixes for lowercase constructor type

Add `expiration` method to TransactionBuilder

Add `code_hash` to Contract constructor

Added `set_signature` method to Transaction

Add new `withdraw_rewards` method

Add event logs parser

And many more...

Internal changes:

Setup CI testing and reformat code with black, isort and flake8
