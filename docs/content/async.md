# Sync and Async

TronPy has one client, [`Tron`][tronpy.Tron]. It is async-native and built on [httpx2](https://pydantic.dev/docs/httpx2/),
and [universalasync](https://github.com/bitcart/universalasync) makes the same methods usable from sync code.

## Using it from sync code

Outside of an event loop, methods run to completion and return their result:

```python
from tronpy import Tron

with Tron(network="nile") as client:
    print(client.get_latest_block_number())
```

## Using it from async code

Inside a running event loop, the same methods return coroutines, so await them:

```python
import asyncio

from tronpy import Tron
from tronpy.keys import PrivateKey

# private key of TMisHYBVvFHwKXHPYTqo8DhrRPTbWeAM6z
priv_key = PrivateKey(bytes.fromhex("8888888888888888888888888888888888888888888888888888888888888888"))


async def transfer():
    async with Tron(network="nile") as client:
        print(client)

        txb = (
            client.trx.transfer("TJzXt1sZautjqXnpjQT4xSCBHNSYgBkDr3", "TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA", 1_000)
            .memo("test memo")
            .fee_limit(100_000_000)
        )
        txn = await txb.build()
        print(txn)
        txn_ret = await txn.sign(priv_key).broadcast()
        print(txn_ret)
        # > {'result': True, 'txid': 'edc2a625752b9c71fdd0d68117802860c6adb1a45c19fd631a41757fa334d72b'}
        print(await txn_ret.wait())
        # > {'id': 'edc2a625752b9c71fdd0d68117802860c6adb1a45c19fd631a41757fa334d72b', 'blockNumber': 10163821,
        # > 'blockTimeStamp': 1603368072000, 'contractResult': [''], 'receipt': {'net_usage': 283}}


if __name__ == "__main__":
    asyncio.run(transfer())
```

## Threads and event loops

A client can be shared between threads and used across repeated `asyncio.run` calls. The provider keeps one
`httpx2.AsyncClient` per event loop, and `client.close()` or leaving `with` / `async with` closes all of them.

## Migrating to the single client

### Names

Use the names without the `Async` prefix, imported from `tronpy`, `tronpy.tron`, `tronpy.contract` and
`tronpy.providers`.

`AsyncTron` and the other `Async*` names still import from their old places, including the `tronpy.async_tron`,
`tronpy.async_contract` and `tronpy.providers.async_http` modules. They are aliases of the new names, kept only so existing
code keeps working, and are not recommended for new code.

### Coming from the sync client

- Catch `httpx2` exceptions, like `httpx2.TimeoutException` and `httpx2.HTTPError`, instead of `requests` ones.
- `HTTPProvider.sess` is gone. Pass `client_factory=lambda: httpx2.AsyncClient(...)` for custom settings, or use the `HTTPS_PROXY` environment variable for proxies.
- TLS verification uses the OS trust store instead of `certifi`.
- Redirects are no longer followed: `httpx2` raises on a `3xx` response, so point `endpoint_uri` at the final URL.
- `HTTPProvider` arguments after `timeout`, like `api_key` and `jw_token`, are keyword-only.
- `Transaction(raw, client=client)` no longer makes a network call. Use `Transaction.create(raw, client=client)` to get the `txID` and permission from the node. When `txid` is passed, `create` makes no call either, so use `check_sign_weight()` if you need the permission checked on `sign`.
- Custom providers must define `make_request` as `async def`.
- Type checkers see the methods as async, so typed sync callers need `cast` or `# type: ignore`, also on `with Tron()`:

```python
from typing import cast

from tronpy import Tron

client = Tron(network="nile")
height = cast(int, client.get_latest_block_number())
```

### Coming from the async client

- Passing `conf={"timeout": ...}` along with a provider now raises `ValueError`. Set the timeout on the provider.
- `provider.client` is now a read-only property returning the client of the current event loop.

### Pitfalls

`asyncio.run(client.method())` raises `ValueError` (`TypeError` on Python 3.14+) after the call has already run, because
outside of an event loop `client.method()` runs right away and `asyncio.run` receives its result instead of a coroutine.
So `asyncio.run(tx.broadcast())` sends the transaction and then raises. Wrap the calls in a coroutine instead:

```python
async def main():
    return await tx.broadcast()


asyncio.run(main())
```

Sync-style calls inside a running event loop return a coroutine and do nothing until awaited. So forgetting `await` on
`tx.broadcast()` in async code sends nothing.

A client passed with `HTTPProvider(client=...)` is only used on the event loop that is current when the provider is
created. Other threads and any later `asyncio.run` use a default client with the provider's `timeout` instead,
without the settings of yours. To use your settings on every event loop, pass
[`client_factory`](client.md#custom-http-client-settings) instead.

## API reference

::: tronpy.Tron

::: tronpy.tron.Trx
