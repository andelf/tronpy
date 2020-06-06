from tronpy import Tron
from tronpy.keys import PrivateKey


def test_client():
    client = Tron()

    print(client)
    priv_key = PrivateKey(bytes.fromhex("8888888888888888888888888888888888888888888888888888888888888888"))

    txn = (
        client.trx.transfer("TJzXt1sZautjqXnpjQT4xSCBHNSYgBkDr3", "TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA", 1_000)
        .memo("test memo")
        .fee_limit(100_000_000)
        .build()
        .inspect()
        .sign(priv_key)
        .broadcast()
    )

    print(txn)
