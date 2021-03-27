# tronpy

[![PyPI version](https://badge.fury.io/py/tronpy.svg)](https://pypi.org/project/tronpy/)

TRON Python Client Library. [Documentation](https://tronpy.readthedocs.io/en/latest/index.html)

## How to use

```python
from tronpy import Tron
from tronpy.keys import PrivateKey

client = Tron(network='nile')
# Private key of TJzXt1sZautjqXnpjQT4xSCBHNSYgBkDr3
priv_key = PrivateKey(bytes.fromhex("8888888888888888888888888888888888888888888888888888888888888888"))

txn = (
    client.trx.transfer("TJzXt1sZautjqXnpjQT4xSCBHNSYgBkDr3", "TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA", 1_000)
    .memo("test memo")
    .build()
    .inspect()
    .sign(priv_key)
    .broadcast()
)

print(txn)
# > {'result': True, 'txid': '5182b96bc0d74f416d6ba8e22380e5920d8627f8fb5ef5a6a11d4df030459132'}
print(txn.wait())
# > {'id': '5182b96bc0d74f416d6ba8e22380e5920d8627f8fb5ef5a6a11d4df030459132', 'blockNumber': 6415370, 'blockTimeStamp': 1591951155000, 'contractResult': [''], 'receipt': {'net_usage': 283}}
```

### Async Client

```python
import asyncio

from tronpy import AsyncTron
from tronpy.keys import PrivateKey

# private key of TMisHYBVvFHwKXHPYTqo8DhrRPTbWeAM6z
priv_key = PrivateKey(bytes.fromhex("8888888888888888888888888888888888888888888888888888888888888888"))

async def transfer():
    async with AsyncTron(network='nile') as client:
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
        # > {'id': 'edc2a625752b9c71fdd0d68117802860c6adb1a45c19fd631a41757fa334d72b', 'blockNumber': 10163821, 'blockTimeStamp': 1603368072000, 'contractResult': [''], 'receipt': {'net_usage': 283}}

if __name__ == '__main__':
    asyncio.run(transfer())
```

Or close async client manually:

```python
from httpx import AsyncClient, Timeout
from tronpy.providers.async_http import AsyncHTTPProvider
from tronpy.defaults import CONF_NILE


async def transfer():
    _http_client = AsyncClient(limits=Limits(max_connections=100, max_keepalive_connections=20),
                               timeout=Timeout(timeout=10, connect=5, read=5))
    provider = AsyncHTTPProvider(CONF_NILE, client=_http_client)
    client = AsyncTron(provider=provider)
    print(client)

    priv_key = PrivateKey(bytes.fromhex("8888888888888888888888888888888888888888888888888888888888888888"))
    txb = (
        client.trx.transfer("TJzXt1sZautjqXnpjQT4xSCBHNSYgBkDr3", "TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA", 1_000)
        .memo("test memo")
        .fee_limit(100_000_000)
    )
    txn = await txb.build()
    print(txn)
    txn_ret = await txn.sign(priv_key).broadcast()

    print(txn_ret)
    print(await txn_ret.wait())
    await client.close()

if __name__ == '__main__':
    asyncio.run(transfer())
```
