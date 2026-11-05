# Release Notes

## Latest changes

**Breaking**: Remove `PrivateKey.from_passphrase` and `get_address_from_passphrase`. They used a single SHA-256 of the passphrase as the private key, which is crackable offline, and existed for compatibility with `wallet/createaddress`, removed from java-tron in 4.7.1.1. Use `generate_address` or a mnemonic instead

**Breaking**: Remove the `sha256` helper from `tronpy.keys`, use `hashlib.sha256` instead

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
