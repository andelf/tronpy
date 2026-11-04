# Sending Transaction

A Transaction in TRON is a system contract call, including TRX transfer, TRC10 transfer, contract call, create contract,
vote witness, create new TRC10 token, and so on. The system contract call will be saved on the blockchain(in a block
as a element in transactions list).

## The routine for sending

A normal routine for sending a transaction is:

```text
Create -> Sign -> Broadcast -> (wait) -> Lookup and get receipt
```

TronPy chooses the [method chaining](https://en.wikipedia.org/wiki/Method_chaining) approach to create,
sign, and broadcast any transaction. All type of transactions can be created via [Tron.trx][tronpy.tron.Trx] object.

```python
from tronpy import Tron
from tronpy.keys import PrivateKey

client = Tron(network="nile")
priv_key = PrivateKey(bytes.fromhex("8888888888888888888888888888888888888888888888888888888888888888"))

txn = (
    client.trx.transfer("TJzXt1sZautjqXnpjQT4xSCBHNSYgBkDr3", "TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA", 1_000)
    .memo("test memo")
    .build()
    .sign(priv_key)
)
print(txn.txid)
print(txn.broadcast().wait())
```

In TronPy, the routine is:

0. Create a [TRON API client][tronpy.Tron]
1. Create a [`TransactionBuilder`][tronpy.tron.TransactionBuilder] via [client.trx.foo][tronpy.tron.Trx] functions
2. Optionally set [`fee_limit`][tronpy.tron.TransactionBuilder.fee_limit], [`memo`][tronpy.tron.TransactionBuilder.memo],
   or [`permission_id`][tronpy.tron.TransactionBuilder.permission_id]
3. Call `builder.`[`build`][tronpy.tron.TransactionBuilder.build], create a [`Transaction`][tronpy.tron.Transaction] object
4. Call `transaction.`[`sign`][tronpy.tron.Transaction.sign], to sign the transaction with a
   [private key][tronpy.keys.PrivateKey]. Multiple calling of `sign` means `multi-sign`
5. Call `transaction.`[`broadcast`][tronpy.tron.Transaction.broadcast], to broadcast the transaction object
6. Optionally call `ret.`[`wait`][tronpy.tron.TransactionRet.wait], to wait and query the transaction receipt

The above steps are made easy through following APIs.

## API reference

::: tronpy.tron.Trx

::: tronpy.tron.TransactionBuilder

::: tronpy.tron.Transaction

::: tronpy.tron.TransactionRet
