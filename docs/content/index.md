# TronPy

TronPy is an easy-to-use TRON HTTP API client. It supports most of the java-tron 4.1 APIs.

/// note
This project is under active development. The APIs may change often.
///

Key principles:

- Never use unsafe API (TronPy always sign offline)
- Always use base58check address (API response, ABI decode/encode, ...)
- Construct transactions offline (more control of ref_block, expiration)

Now, [click here to start your tour with TronPy](quickstart.md).
