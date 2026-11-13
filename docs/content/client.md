# HTTP API Client

TronPy uses TRON HTTP API to communicate with TRON nodes. The main client class is [`Tron`][tronpy.Tron].

## Creating client

Refer [Quickstart](quickstart.md) for creating clients.

## Calling query APIs

The [`Tron`][tronpy.Tron] wraps many query APIs and utility functions. You can query the chain using a instance.

```python
>>> from tronpy import Tron
>>> client = Tron()
>>> client.get_latest_block_number()
20746184
>>> client.get_latest_block_id()
'00000000013c8fc9a74d2ef9111d2216b9bec4b0fbf44e2e77711dde0e535f8e'
>>> client.get_account_balance('TTzPiwbBedv7E8p4FkyPyeqq4RVoqRL3TW')
Decimal('286820.078511')
>>> client.get_account_asset_balance('TCrahg7N9cB1SwN21WzVMqxCptbRdvQata', 1002928)
989937719235000000

>>> client.generate_address()
{'base58check_address': 'TU7r98aQ3XTHuM9NLwnyVmdCH7gAZDYqxt',
 'hex_address': '41c71498123f6de4698410712e5f5c96ae42978776',
 'private_key': '.................omitted.....................',
 'public_key': '..................omitted.....................'}
```

## Using TronGrid API Key

You can register an API Key at [TronGrid](https://www.trongrid.io/).

```python
from tronpy import Tron
from tronpy.providers import HTTPProvider

client = Tron(HTTPProvider(api_key="Your api_key here"))  # Use mainnet(trongrid) with a single api_key

# or

client = Tron(HTTPProvider(api_key=["key1", "key2", "key3"]))  # Use mainnet(trongrid) with multiple api_key
```

## Use HTTP Proxy

```python
from tronpy import Tron
from tronpy.providers import HTTPProvider

client = Tron(HTTPProvider(api_key="API KEY HERE"))  # with HTTPS_PROXY and HTTP_PROXY set in the environment
```

## Custom HTTP client settings

Pass `client_factory` to set a proxy, limits, TLS verification or anything else `httpx2.AsyncClient` accepts. It is called
once per event loop, so your settings apply on all threads and across repeated `asyncio.run` calls. The `timeout`
of `HTTPProvider` doesn't apply to these clients, so set it in the factory.

```python
import httpx2

from tronpy import Tron
from tronpy.providers import HTTPProvider


def create_client():
    return httpx2.AsyncClient(proxy="http://....", timeout=httpx2.Timeout(10.0))


client = Tron(HTTPProvider(api_key="API KEY HERE", client_factory=create_client))
```

Passing a single client with `client=` instead only applies to [the event loop it was created for](async.md#pitfalls).

## API reference

::: tronpy.Tron

::: tronpy.providers.HTTPProvider
