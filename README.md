# tronpy

[![PyPI version](https://badge.fury.io/py/tronpy.svg)](https://pypi.org/project/tronpy/)

TRON Python Client Library. [Documentation](https://tronpy.readthedocs.io/en/latest/index.html)

## How to use

```python
from tronpy import Tron

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
