import asyncio
import json
import socket
import time
from unittest.mock import AsyncMock, patch

import pytest
from httpx2 import AsyncClient, Limits, Timeout, TimeoutException

from tests.utils import check_generate_address, check_transaction_structure
from tronpy import Tron
from tronpy.defaults import CONF_NILE
from tronpy.keys import PrivateKey
from tronpy.providers import HTTPProvider
from tronpy.tron import Transaction, TransactionRet

# test_net address
FROM_ADDR = "TPX6HK2NRN4XKRX1JAhbC827bm7gMmy5w1"
# test_net private key
FROM_PRIV_KEY = PrivateKey(bytes.fromhex("279ff36d9bf9f305af3280034bb4187c6dd299bac6b26a3c20b999c7c0d50e6e"))
# test_net address
TO_ADDR = "TFVfhkyJAULWQbHMgVfgbkmgeGBkHo5zru"
CNR_ADDR = "THi2qJf6XmvTJSpZHc17HgQsmJop6kb3ia"

TRANSFER_EXPECTED_RESP = {
    "parameter": {
        "value": {
            "owner_address": "4194a15629b2b2bbd3a5453e6d6696b2875278633b",
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
            "owner_address": "4194a15629b2b2bbd3a5453e6d6696b2875278633b",
            "to_address": "413c9b65b212316904572826240224750eccce29a2",
            "amount": 1000000,
            "asset_name": "31303030303437",
        },
        "type_url": "type.googleapis.com/protocol.TransferAssetContract",
    },
    "type": "TransferAssetContract",
}

TRANSACTION_JSON = {
    "txID": "c93cdd6b4d9f5b3c617060ea0a9c7b6080d9855f599cc987f69105a5e3e9c9b4",
    "raw_data": {
        "contract": [TRANSFER_EXPECTED_RESP],
        "timestamp": 1751466432131,
        "expiration": 1751466492131,
        "ref_block_bytes": "6431",
        "ref_block_hash": "212a13dbe72ac5c0",
    },
    "raw_data_hex": "0a0264312208212a13dbe72ac5c040e381a7dcfc325a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a154194a15629b2b2bbd3a5453e6d6696b2875278633b1215413c9b65b212316904572826240224750eccce29a218017083ada3dcfc32",  # noqa: E501
    "signature": [],
    "permission": None,
}


@pytest.fixture
def stalled_node():
    with socket.create_server(("127.0.0.1", 0)) as server:
        yield f"http://127.0.0.1:{server.getsockname()[1]}"


def test_client_keygen():
    client = Tron()
    check_generate_address(client.generate_address())


@pytest.mark.asyncio
async def test_client_sign_offline():
    async with Tron(network="nile") as client:
        tx = await client.trx.transfer(FROM_ADDR, TO_ADDR, 1).memo("test memo").fee_limit(100_000_000).build()
        tx_j = tx.to_json()
        check_transaction_structure(tx_j, TRANSFER_EXPECTED_RESP, 100_000_000, expect_signature=False)
        # offline
        tx_offline = await Transaction.from_json(tx_j)  # tx_offline._client is None so it's offline
        tx_offline.sign(FROM_PRIV_KEY)
        tx_j2 = tx_offline.to_json()
        check_transaction_structure(tx_j2, TRANSFER_EXPECTED_RESP, 100_000_000)
        # online
        tx_2 = await Transaction.from_json(tx_j2, client=client)
        check_transaction_structure(tx_2.to_json(), TRANSFER_EXPECTED_RESP, 100_000_000)


@pytest.mark.asyncio
async def test_client_update_tx():
    async with Tron(network="nile") as client:
        tx = await client.trx.transfer(FROM_ADDR, TO_ADDR, 1).memo("test memo").fee_limit(100_000_000).build()
        tx.sign(FROM_PRIV_KEY)
        tx_id = tx.txid
        await asyncio.sleep(0.01)
        await tx.update()
        assert tx_id != tx.txid
        assert tx._signature == []
        check_transaction_structure(tx.to_json(), TRANSFER_EXPECTED_RESP, 100_000_000, expect_signature=False)


@pytest.mark.parametrize("serialize", [json.dumps, lambda data: data], ids=["str", "dict"])
@pytest.mark.asyncio
async def test_transaction_from_json(serialize):
    tx = await Transaction.from_json(serialize(TRANSACTION_JSON))
    assert tx.to_json() == TRANSACTION_JSON


def test_transaction_from_full_transaction_dict():
    assert Transaction(TRANSACTION_JSON).to_json() == TRANSACTION_JSON


@pytest.mark.asyncio
async def test_client():
    async with Tron(network="nile") as client:
        tx = (await client.trx.transfer(FROM_ADDR, TO_ADDR, 1).memo("test memo").fee_limit(100_000_000).build()).sign(
            FROM_PRIV_KEY
        )
        check_transaction_structure(tx.to_json(), TRANSFER_EXPECTED_RESP, 100_000_000)


@pytest.mark.asyncio
async def test_manual_client():
    _http_client = AsyncClient(
        limits=Limits(max_connections=100, max_keepalive_connections=20),
        timeout=Timeout(timeout=10, connect=5, read=5),
    )
    provider = HTTPProvider(CONF_NILE, client=_http_client)
    client = Tron(provider=provider)

    tx = (await client.trx.transfer(FROM_ADDR, TO_ADDR, 1).memo("test memo").fee_limit(100_000_000).build()).sign(
        FROM_PRIV_KEY
    )
    check_transaction_structure(tx.to_json(), TRANSFER_EXPECTED_RESP, 100_000_000)

    # must call .close at end to release connections
    await client.close()


@pytest.mark.asyncio
async def test_client_get_contract():
    async with Tron(network="nile") as client:
        cntr = await client.get_contract("TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf")
        assert cntr
        assert cntr.abi
        assert await cntr.functions.name()


@pytest.mark.asyncio
async def test_client_transfer_trc10():
    async with Tron(network="nile") as client:
        tx = (
            await client.trx.asset_transfer(FROM_ADDR, TO_ADDR, 1_000000, token_id=1000047)
            .memo("test transfer coin")
            .fee_limit(0)
            .build()
        ).sign(FROM_PRIV_KEY)
        check_transaction_structure(tx.to_json(), TRANSFER_TRC10_EXPECTED_RESP, 0)


@pytest.mark.asyncio
async def test_client_timeout(stalled_node):
    async with Tron(network="nile", conf={"timeout": 0.01}) as client:
        client.provider.endpoint_uri = stalled_node
        with pytest.raises(TimeoutException):
            await client.get_block()


def test_unknown_network_is_rejected():
    with pytest.raises(ValueError, match="unknown network 'nil'"):
        Tron(network="nil")


@pytest.mark.asyncio
async def test_get_asset_rejects_id_and_issuer_together():
    with pytest.raises(ValueError, match="either query by id or issuer"):
        await Tron(network="nile").get_asset(1000001, FROM_ADDR)


def test_sign_without_client_or_known_permission():
    expiration = int(time.time() * 1000) + 60_000
    transaction = Transaction({"expiration": expiration}, txid="00" * 32).sign(FROM_PRIV_KEY)
    assert len(transaction.to_json()["signature"]) == 1


@pytest.mark.asyncio
async def test_building_a_transaction_does_not_reach_the_node():
    raw_data = TRANSACTION_JSON["raw_data"]
    with patch.object(HTTPProvider, "make_request", AsyncMock(return_value={})) as node:
        client = Tron(network="nile")
        transaction = Transaction(raw_data, client=client)
        node.assert_not_awaited()
        assert transaction.txid == ""


@pytest.mark.asyncio
async def test_create_fetches_txid_and_permission_from_the_node():
    transaction = {"txID": TRANSACTION_JSON["txID"], "raw_data_hex": TRANSACTION_JSON["raw_data_hex"]}
    permission = {"keys": []}
    response = {"transaction": {"transaction": transaction}, "permission": permission}
    with patch.object(HTTPProvider, "make_request", AsyncMock(return_value=response)) as node:
        created = await Transaction.create(TRANSACTION_JSON["raw_data"], client=Tron(network="nile"))
    node.assert_awaited_once()
    assert created.txid == TRANSACTION_JSON["txID"]
    assert created.raw_data_hex == TRANSACTION_JSON["raw_data_hex"]
    assert created._permission == permission


@pytest.mark.asyncio
async def test_create_without_txid_needs_a_client():
    with pytest.raises(TypeError, match="transaction has no client"):
        await Transaction.create(TRANSACTION_JSON["raw_data"])


@pytest.mark.asyncio
async def test_broadcast_keeps_txid_when_node_omits_it():
    transaction = Transaction(TRANSACTION_JSON, client=Tron(network="nile"))
    with patch.object(HTTPProvider, "make_request", AsyncMock(return_value={"result": True})):
        ret = await transaction.broadcast()
    assert isinstance(ret, TransactionRet)
    assert ret.txid == TRANSACTION_JSON["txID"]


def test_timeout_in_conf_conflicts_with_provider():
    with pytest.raises(ValueError, match="timeout value should be set in provider"):
        Tron(HTTPProvider(CONF_NILE), conf={"timeout": 1.0})
    assert Tron(HTTPProvider(CONF_NILE), conf={"fee_limit": 1}).conf["fee_limit"] == 1
