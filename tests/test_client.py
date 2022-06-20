import time

from tronpy import Tron, AsyncTron
from tronpy.keys import PrivateKey
from tronpy.tron import Transaction
from tronpy.async_tron import AsyncTransaction
import pytest

# test_net address
FROM_ADDR = '8888888888888888888888888888888888'
# test_net private key
FROM_PRIV_KEY = PrivateKey(bytes.fromhex("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"))
# test_net address
TO_ADDR = '7777777777777777777777777777777777'
CNR_ADDR = "THi2qJf6XmvTJSpZHc17HgQsmJop6kb3ia"


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

    txn = (
        client.trx.transfer(FROM_ADDR, TO_ADDR, 1_000)
        .memo("test memo")
        .fee_limit(100_000_000)
        .build()
        .inspect()
        .sign(FROM_PRIV_KEY)
        .broadcast()
    )

    print(txn)


def test_client_sign_offline():
    client = Tron(network='nile')
    tx = client.trx.transfer(
        FROM_ADDR, TO_ADDR, 1
    ).memo("test memo").fee_limit(100_000_000).build()
    tx_j = tx.to_json()
    # offline
    tx_offline = Transaction.from_json(tx_j)    # tx_offline._client is None so it's offline
    tx_offline.sign(FROM_PRIV_KEY)
    tx_j2 = tx_offline.to_json()
    # online
    tx_2 = Transaction.from_json(tx_j2, client=client)
    tx_2.broadcast()


@pytest.mark.asyncio
async def test_async_client_sign_offline():
    async with AsyncTron(network='nile') as client:
        tx = await client.trx.transfer(
            FROM_ADDR, TO_ADDR, 1
        ).memo("test memo").fee_limit(100_000_000).build()
        tx_j = tx.to_json()
        # offline
        tx_offline = await AsyncTransaction.from_json(tx_j)    # tx_offline._client is None so it's offline
        tx_offline.sign(FROM_PRIV_KEY)
        tx_j2 = tx_offline.to_json()
        # online
        tx_2 = await AsyncTransaction.from_json(tx_j2, client=client)
        await tx_2.broadcast()


def test_client_update_tx():
    client = Tron(network='nile')
    tx: Transaction = client.trx.transfer(
        FROM_ADDR, TO_ADDR, 1
    ).memo("test memo").fee_limit(100_000_000).build()
    tx.sign(FROM_PRIV_KEY)
    tx.broadcast()
    tx_id = tx.txid
    # update and transfer again
    time.sleep(0.01)
    tx.update()
    assert tx_id != tx.txid
    assert tx._signature == []
    tx.sign(FROM_PRIV_KEY)
    tx.broadcast()


@pytest.mark.asyncio
async def test_async_client():
    async with AsyncTron(network='nile') as client:
        txb = (
            client.trx.transfer(FROM_ADDR, TO_ADDR, 1_000)
            .memo("test memo")
            .fee_limit(100_000_000)
        )
        txn = await txb.build()
        txn.inspect()
        txn_ret = await txn.sign(FROM_PRIV_KEY).broadcast()

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

    txb = (
        client.trx.transfer(FROM_ADDR, TO_ADDR, 1_000)
        .memo("test memo")
        .fee_limit(1_000_000)
    )
    txn = await txb.build()
    txn_ret = await txn.sign(FROM_PRIV_KEY).broadcast()

    print(txn_ret)
    print(await txn_ret.wait())

    # must call .close at end to release connections
    await client.close()


def test_client_get_contract():
    client = Tron()
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

    cntr = client.get_contract("TMDRdYAcXbQDajbGFy4rgXcNLYswuYsfk1")
    assert cntr
    assert cntr.abi
    assert cntr.functions.name()


@pytest.mark.asyncio
async def test_async_client_get_contract():
    async with AsyncTron() as client:
        cntr = await client.get_contract("TMDRdYAcXbQDajbGFy4rgXcNLYswuYsfk1")
        assert cntr
        assert cntr.abi
        assert cntr.functions.name()


def test_client_transfer_trc10():
    client = Tron(network='nile')

    txn = (
        client.trx.asset_transfer(
            FROM_ADDR, TO_ADDR, 1_000000, token_id=1000047
        )
        .memo("test transfer coin")
        .fee_limit(0)
        .build()
        .inspect()
        .sign(FROM_PRIV_KEY)
        .broadcast()
    )

    print(txn)


@pytest.mark.asyncio
async def test_client_transfer_trc10():
    async with AsyncTron(network='nile') as client:
        txb = (
            client.trx.asset_transfer(
                FROM_ADDR, TO_ADDR, 1_000, token_id=1000016
            )
            .memo("test transfer coin")
            .fee_limit(0)
        )
        txn = await txb.build()
        txn.inspect()
        txn = txn.sign(FROM_PRIV_KEY)
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
