import time

from tronpy import Tron, AsyncTron
from tronpy.keys import PrivateKey
from tronpy.tron import Transaction
import pytest


def test_client_keygen():
    client = Tron()
    print(client.generate_address())
    print(client.get_address_from_passphrase('A'))


@pytest.mark.asyncio
def test_async_client_keygen():
    client = AsyncTron()
    print(client.generate_address())
    print(client.get_address_from_passphrase('A'))


def test_client():
    client = Tron(network='nile')

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


def test_client_sign_offline():
    client = Tron(network='nile')
    priv_key = PrivateKey(bytes.fromhex("8888888888888888888888888888888888888888888888888888888888888888"))
    tx = client.trx.transfer(
        "TJzXt1sZautjqXnpjQT4xSCBHNSYgBkDr3", "TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA", 1
    ).memo("test memo").fee_limit(100_000_000).build()
    tx_j = tx.to_json()
    # offline
    tx_offline = Transaction.from_json(tx_j)    # tx_offline._client is None so it's offline
    tx_offline.sign(priv_key)
    tx_j2 = tx_offline.to_json()
    # online
    tx_2 = Transaction.from_json(tx_j2, client=client)
    tx_2.broadcast()


def test_client_update_tx():
    client = Tron(network='nile')
    priv_key = PrivateKey(bytes.fromhex("8888888888888888888888888888888888888888888888888888888888888888"))
    tx: Transaction = client.trx.transfer(
        "TJzXt1sZautjqXnpjQT4xSCBHNSYgBkDr3", "TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA", 1
    ).memo("test memo").fee_limit(100_000_000).build()
    tx.sign(priv_key)
    tx.broadcast()
    tx_id = tx.txid
    # update and transfer again
    time.sleep(0.01)
    tx.update()
    assert tx_id != tx.txid
    assert tx._signature == []
    tx.sign(priv_key)
    tx.broadcast()


@pytest.mark.asyncio
async def test_async_client():
    async with AsyncTron(network='nile') as client:
        print(client)
        priv_key = PrivateKey(bytes.fromhex("8888888888888888888888888888888888888888888888888888888888888888"))

        txb = (
            client.trx.transfer("TJzXt1sZautjqXnpjQT4xSCBHNSYgBkDr3", "TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA", 1_000)
            .memo("test memo")
            .fee_limit(100_000_000)
        )
        txn = await txb.build()
        txn.inspect()
        txn_ret = await txn.sign(priv_key).broadcast()

        print(txn_ret)
        print(await txn_ret.wait())


@pytest.mark.asyncio
async def test_async_manual_client():
    from httpx import AsyncClient, Timeout, Limits
    from tronpy.providers.async_http import AsyncHTTPProvider
    from tronpy.defaults import CONF_NILE

    _http_client = AsyncClient(
        limits=Limits(max_connections=100, max_keepalive_connections=20), timeout=Timeout(timeout=10, connect=5, read=5)
    )
    provider = AsyncHTTPProvider(CONF_NILE, client=_http_client)
    client = AsyncTron(provider=provider)

    priv_key = PrivateKey(bytes.fromhex("8888888888888888888888888888888888888888888888888888888888888888"))
    txb = (
        client.trx.transfer("TJzXt1sZautjqXnpjQT4xSCBHNSYgBkDr3", "TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA", 1_000)
        .memo("test memo")
        .fee_limit(1_000_000)
    )
    txn = await txb.build()
    txn_ret = await txn.sign(priv_key).broadcast()

    print(txn_ret)
    print(await txn_ret.wait())

    # must call .close at end to release connections
    await client.close()


def test_client_get_contract():
    client = Tron()
    priv_key = PrivateKey(bytes.fromhex("ebf7c9cad1ca710553c22669fd3c7c70832e7024c1a32da69bbc5ad19dcc8992"))

    """
    txn = (
        client.trx.asset_issue(
            "TGxv9UXRNMh4E6b33iuH1pqJfBffz6hXnV", "BTCC", 1_0000_0000_000000, url="https://www.example.com"
        )
        .memo("test issue BTCC coin")
        .fee_limit(0)
        .build()
        .inspect()
        .sign(priv_key)
        # .broadcast()
    )

    print(txn)
    """

    # print(client.get_account_permission("TGxv9UXRNMh4E6b33iuH1pqJfBffz6hXnV"))

    # very old address, of mainnet
    # print(client.get_account_resource("TTjacDH5PL8hpWirqU7HQQNZDyF723PuCg"))
    # "TGj1Ej1qRzL9feLTLhjwgxXF4Ct6GTWg2U"))

    cntr = client.get_contract("TMDRdYAcXbQDajbGFy4rgXcNLYswuYsfk1")
    print(cntr)

    print(cntr.abi)
    # print(client.get_contract("TTjacDH5PL8hpWirqU7HQQNZDyF723PuCg"))

    cntr.functions.name()


@pytest.mark.asyncio
async def test_async_client_get_contract():
    async with AsyncTron() as client:
        cntr = await client.get_contract("TMDRdYAcXbQDajbGFy4rgXcNLYswuYsfk1")
        print(cntr)

        print(cntr.abi)
        # print(client.get_contract("TTjacDH5PL8hpWirqU7HQQNZDyF723PuCg"))

        print(await cntr.functions.name())


def test_client_transfer_trc10():
    client = Tron(network='nile')

    priv_key = PrivateKey(bytes.fromhex("ebf7c9cad1ca710553c22669fd3c7c70832e7024c1a32da69bbc5ad19dcc8992"))

    txn = (
        client.trx.asset_transfer(
            "TGxv9UXRNMh4E6b33iuH1pqJfBffz6hXnV", "TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA", 1_000000, token_id=1000047
        )
        .memo("test transfer coin")
        .fee_limit(0)
        .build()
        .inspect()
        .sign(priv_key)
        .broadcast()
    )

    print(txn)


@pytest.mark.asyncio
async def test_client_transfer_trc10():
    async with AsyncTron(network='nile') as client:
        priv_key = PrivateKey(bytes.fromhex("ebf7c9cad1ca710553c22669fd3c7c70832e7024c1a32da69bbc5ad19dcc8992"))

        txb = (
            client.trx.asset_transfer(
                "TGxv9UXRNMh4E6b33iuH1pqJfBffz6hXnV", "TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA", 1_000, token_id=1000047
            )
            .memo("test transfer coin")
            .fee_limit(0)
        )
        txn = await txb.build()
        txn.inspect()
        txn = txn.sign(priv_key)
        txn_ret = await txn.broadcast()
        print(txn_ret)


def test_client_timeout():
    import requests.exceptions

    # must be a timeout
    client = Tron(network='nile', conf={'timeout': 0.0001})

    with pytest.raises(requests.exceptions.Timeout):
        client.get_block()


@pytest.mark.asyncio
async def test_async_client_timeout():
    from httpx import TimeoutException

    # must be a timeout
    async with AsyncTron(network='nile', conf={'timeout': 0.0001}) as client:
        with pytest.raises(TimeoutException):
            await client.get_block()
