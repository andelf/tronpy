import time

import pytest

from tests.utils import check_generate_address, check_transaction_structure
from tronpy import AsyncTron, Tron
from tronpy.async_tron import AsyncTransaction
from tronpy.keys import PrivateKey
from tronpy.tron import Transaction

# test_net address
FROM_ADDR = "TBDCyrZ1hT1PDDFf2yRABwPrFica5qqPUX"
# test_net private key
FROM_PRIV_KEY = PrivateKey(bytes.fromhex("fd605fb953fcdabb952be161265a75b8a3ce1c0def2c7db72265f9db9a471be4"))
# test_net address
TO_ADDR = "TFVfhkyJAULWQbHMgVfgbkmgeGBkHo5zru"
CNR_ADDR = "THi2qJf6XmvTJSpZHc17HgQsmJop6kb3ia"

TRANSFER_EXPECTED_RESP = {
    "parameter": {
        "value": {
            "owner_address": "410d9dee927cc1ea6b6e67f4993fac317826ea0c26",
            "to_address": "413c9b65b212316904572826240224750eccce29a2",
            "amount": 1,
        },
        "type_url": "type.googleapis.com/protocol.TransferContract",
    },
    "type": "TransferContract",
}

TRANSFER_TRC10_EXPECTED_RESP = {
    "parameter": {
        "value": {
            "owner_address": "410d9dee927cc1ea6b6e67f4993fac317826ea0c26",
            "to_address": "413c9b65b212316904572826240224750eccce29a2",
            "amount": 1000000,
            "asset_name": "31303030303437",
        },
        "type_url": "type.googleapis.com/protocol.TransferAssetContract",
    },
    "type": "TransferAssetContract",
}


def test_client_keygen():
    client = Tron()
    check_generate_address(client.generate_address())
    check_generate_address(client.get_address_from_passphrase("A"))


@pytest.mark.asyncio
async def test_async_client_keygen():
    client = AsyncTron()
    check_generate_address(client.generate_address())
    check_generate_address(client.get_address_from_passphrase("A"))


def test_client():
    client = Tron(network="nile")

    tx = (
        client.trx.transfer(FROM_ADDR, TO_ADDR, 1)
        .memo("test memo")
        .fee_limit(100_000_000)
        .build()
        .sign(FROM_PRIV_KEY)
        .to_json()
    )
    check_transaction_structure(tx, TRANSFER_EXPECTED_RESP, 100_000_000)


def test_client_sign_offline():
    client = Tron(network="nile")
    tx = client.trx.transfer(FROM_ADDR, TO_ADDR, 1).memo("test memo").fee_limit(100_000_000).build()
    tx_j = tx.to_json()
    check_transaction_structure(tx_j, TRANSFER_EXPECTED_RESP, 100_000_000, expect_signature=False)
    # offline
    tx_offline = Transaction.from_json(tx_j)  # tx_offline._client is None so it's offline
    tx_offline.sign(FROM_PRIV_KEY)
    tx_j2 = tx_offline.to_json()
    check_transaction_structure(tx_j2, TRANSFER_EXPECTED_RESP, 100_000_000)
    # online
    tx_2 = Transaction.from_json(tx_j2, client=client)
    check_transaction_structure(tx_2.to_json(), TRANSFER_EXPECTED_RESP, 100_000_000)


@pytest.mark.asyncio
async def test_async_client_sign_offline():
    async with AsyncTron(network="nile") as client:
        tx = await client.trx.transfer(FROM_ADDR, TO_ADDR, 1).memo("test memo").fee_limit(100_000_000).build()
        tx_j = tx.to_json()
        check_transaction_structure(tx_j, TRANSFER_EXPECTED_RESP, 100_000_000, expect_signature=False)
        # offline
        tx_offline = await AsyncTransaction.from_json(tx_j)  # tx_offline._client is None so it's offline
        tx_offline.sign(FROM_PRIV_KEY)
        tx_j2 = tx_offline.to_json()
        check_transaction_structure(tx_j2, TRANSFER_EXPECTED_RESP, 100_000_000)
        # online
        tx_2 = await AsyncTransaction.from_json(tx_j2, client=client)
        check_transaction_structure(tx_2.to_json(), TRANSFER_EXPECTED_RESP, 100_000_000)


def test_client_update_tx():
    client = Tron(network="nile")
    tx: Transaction = client.trx.transfer(FROM_ADDR, TO_ADDR, 1).memo("test memo").fee_limit(100_000_000).build()
    tx.sign(FROM_PRIV_KEY)
    tx_id = tx.txid
    # update and transfer again
    time.sleep(0.01)
    tx.update()
    assert tx_id != tx.txid
    assert tx._signature == []


@pytest.mark.asyncio
async def test_async_client():
    async with AsyncTron(network="nile") as client:
        tx = (await client.trx.transfer(FROM_ADDR, TO_ADDR, 1).memo("test memo").fee_limit(100_000_000).build()).sign(
            FROM_PRIV_KEY
        )
        check_transaction_structure(tx.to_json(), TRANSFER_EXPECTED_RESP, 100_000_000)


@pytest.mark.asyncio
async def test_async_manual_client():
    from httpx import AsyncClient, Limits, Timeout

    from tronpy.defaults import CONF_NILE
    from tronpy.providers.async_http import AsyncHTTPProvider

    _http_client = AsyncClient(
        limits=Limits(max_connections=100, max_keepalive_connections=20),
        timeout=Timeout(timeout=10, connect=5, read=5),
    )
    provider = AsyncHTTPProvider(CONF_NILE, client=_http_client)
    client = AsyncTron(provider=provider)

    tx = (await client.trx.transfer(FROM_ADDR, TO_ADDR, 1).memo("test memo").fee_limit(100_000_000).build()).sign(
        FROM_PRIV_KEY
    )
    check_transaction_structure(tx.to_json(), TRANSFER_EXPECTED_RESP, 100_000_000)

    # must call .close at end to release connections
    await client.close()


def test_client_get_contract():
    client = Tron(network="nile")
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

    cntr = client.get_contract("TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf")
    assert cntr
    assert cntr.abi
    assert cntr.functions.name()


@pytest.mark.asyncio
async def test_async_client_get_contract():
    async with AsyncTron(network="nile") as client:
        cntr = await client.get_contract("TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf")
        assert cntr
        assert cntr.abi
        assert await cntr.functions.name()


def test_client_transfer_trc10():
    client = Tron(network="nile")

    tx = (
        client.trx.asset_transfer(FROM_ADDR, TO_ADDR, 1_000000, token_id=1000047)
        .memo("test transfer coin")
        .fee_limit(0)
        .build()
        .sign(FROM_PRIV_KEY)
    )
    check_transaction_structure(tx.to_json(), TRANSFER_TRC10_EXPECTED_RESP, 0)


@pytest.mark.asyncio
async def test_async_client_transfer_trc10():
    async with AsyncTron(network="nile") as client:
        tx = (
            await client.trx.asset_transfer(FROM_ADDR, TO_ADDR, 1_000000, token_id=1000047)
            .memo("test transfer coin")
            .fee_limit(0)
            .build()
        ).sign(FROM_PRIV_KEY)
        check_transaction_structure(tx.to_json(), TRANSFER_TRC10_EXPECTED_RESP, 0)


def test_client_timeout():
    import requests.exceptions

    # must be a timeout
    client = Tron(network="nile", conf={"timeout": 0.0001})

    with pytest.raises(requests.exceptions.Timeout):
        client.get_block()


@pytest.mark.asyncio
async def test_async_client_timeout():
    from httpx import TimeoutException

    # must be a timeout
    async with AsyncTron(network="nile", conf={"timeout": 0.0001}) as client:
        with pytest.raises(TimeoutException):
            await client.get_block()
