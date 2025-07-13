import asyncio
import datetime
import importlib
import typing
from unittest.mock import patch

import freezegun
import pytest

from tronpy.async_tron import AsyncTron
from tronpy.defaults import PROTOBUF_NOT_INSTALLED_ERROR_MESSAGE
from tronpy.exceptions import ProtobufImportError
from tronpy.tron import Tron

try:
    from tronpy import proto
except ProtobufImportError:
    proto = None
    protobuf_installed = False
else:
    protobuf_installed = True

FROM_ADDR = "TPX6HK2NRN4XKRX1JAhbC827bm7gMmy5w1"
FROM_ADDR_RAW = "4194a15629b2b2bbd3a5453e6d6696b2875278633b"
TO_ADDR = "TFVfhkyJAULWQbHMgVfgbkmgeGBkHo5zru"
TO_ADDR_RAW = "413c9b65b212316904572826240224750eccce29a2"
TRC20_CONTRACT = "THi2qJf6XmvTJSpZHc17HgQsmJop6kb3ia"
TRC20_CONTRACT_RAW = "4154e24764f19b0450d49d4b66270da289666cf82a"
REF_BLOCK_ID = "0000000003546431212a13dbe72ac5c09a684deb83257258a6fcdc1115835077"
REF_BLOCK_BYTES = "6431"
REF_BLOCK_HASH = "212a13dbe72ac5c0"
FEE_LIMIT = 50000000


@pytest.fixture()
def set_protobuf_unavailable() -> typing.Generator[None, None, None]:
    importlib.import_module("tronpy.tron").proto = None
    importlib.import_module("tronpy.async_tron").proto = None
    yield
    importlib.import_module("tronpy.tron").proto = proto
    importlib.import_module("tronpy.async_tron").proto = proto


@pytest.mark.usefixtures("set_protobuf_unavailable")
@pytest.mark.parametrize("client_class", [Tron, AsyncTron])
def test_offline_transfer_raises_import_error(
    client_class: typing.Union[Tron, AsyncTron],
) -> None:
    client = client_class(network="nile")
    if client_class == AsyncTron:

        async def run_test():
            return await client.trx.transfer(FROM_ADDR, TO_ADDR, 1).build(offline=True, ref_block_id="ref_block_id")

        with pytest.raises(ImportError) as exc_info:
            asyncio.run(run_test())
    else:
        with pytest.raises(ImportError) as exc_info:
            client.trx.transfer(FROM_ADDR, TO_ADDR, 1).build(offline=True, ref_block_id="ref_block_id")
    assert exc_info.value.args[0] == PROTOBUF_NOT_INSTALLED_ERROR_MESSAGE


@pytest.mark.usefixtures("set_protobuf_unavailable")
@pytest.mark.parametrize("client_class", [Tron, AsyncTron])
def test_offline_contract_transfer_raises_import_error(
    client_class: typing.Union[Tron, AsyncTron],
) -> None:
    client = client_class(network="nile")
    if client_class == AsyncTron:
        import asyncio

        async def run_contract_test():
            contract = await client.get_contract(TRC20_CONTRACT)
            builder = await contract.functions.transfer(TO_ADDR, 1)
            return await builder.with_owner(FROM_ADDR).fee_limit(FEE_LIMIT).build(offline=True, ref_block_id="ref_block_id")

        with pytest.raises(ImportError) as exc_info:
            asyncio.run(run_contract_test())
    else:
        contract = client.get_contract(TRC20_CONTRACT)
        with pytest.raises(ImportError) as exc_info:
            contract.functions.transfer(TO_ADDR, 1).with_owner(FROM_ADDR).fee_limit(FEE_LIMIT).build(
                offline=True, ref_block_id="ref_block_id"
            )
    assert exc_info.value.args[0] == PROTOBUF_NOT_INSTALLED_ERROR_MESSAGE


@pytest.mark.skipif(not protobuf_installed, reason="Protobuf not installed")
@pytest.mark.parametrize("client_class", [Tron, AsyncTron])
@freezegun.freeze_time(datetime.datetime(2025, 7, 2, 14, 27, 12, 131000, tzinfo=datetime.timezone.utc))
def test_create_transaction_offline(
    client_class: typing.Union[Tron, AsyncTron],
) -> None:
    client = client_class(network="nile")
    if client_class == AsyncTron:

        async def run_test():
            return await client.trx.transfer(FROM_ADDR, TO_ADDR, 1).build(offline=True, ref_block_id=REF_BLOCK_ID)

        transaction = asyncio.run(run_test())
    else:
        transaction = client.trx.transfer(FROM_ADDR, TO_ADDR, 1).build(offline=True, ref_block_id=REF_BLOCK_ID)
    assert transaction.to_json() == {
        "txID": "c93cdd6b4d9f5b3c617060ea0a9c7b6080d9855f599cc987f69105a5e3e9c9b4",
        "raw_data": {
            "contract": [
                {
                    "parameter": {
                        "value": {
                            "owner_address": FROM_ADDR_RAW,
                            "to_address": TO_ADDR_RAW,
                            "amount": 1,
                        },
                        "type_url": "type.googleapis.com/protocol.TransferContract",
                    },
                    "type": "TransferContract",
                }
            ],
            "timestamp": 1751466432131,
            "expiration": 1751466492131,
            "ref_block_bytes": "6431",
            "ref_block_hash": "212a13dbe72ac5c0",
        },
        "signature": [],
        "permission": None,
    }


@pytest.mark.skipif(not protobuf_installed, reason="Protobuf not installed")
@pytest.mark.parametrize("client_class", [Tron, AsyncTron])
@freezegun.freeze_time(datetime.datetime(2025, 7, 3, 14, 50, 32, 807000, tzinfo=datetime.timezone.utc))
def test_create_smart_contract_transaction_offline(
    client_class: typing.Union[Tron, AsyncTron],
) -> None:
    client = client_class(network="nile")
    if client_class == AsyncTron:

        async def run_test():
            contract = await client.get_contract(TRC20_CONTRACT)
            builder = await contract.functions.transfer(TO_ADDR, 1)
            return await builder.with_owner(FROM_ADDR).fee_limit(FEE_LIMIT).build(offline=True, ref_block_id=REF_BLOCK_ID)

        transaction = asyncio.run(run_test())
    else:
        contract = client.get_contract(TRC20_CONTRACT)
        transaction = (
            contract.functions.transfer(TO_ADDR, 1)
            .with_owner(FROM_ADDR)
            .fee_limit(FEE_LIMIT)
            .build(offline=True, ref_block_id=REF_BLOCK_ID)
        )
    assert transaction.to_json() == {
        "txID": "cc0928c7734c9c9cc8e8e9636c3ad47308197f4b42fce6b93eb6fa4b3247b58f",
        "raw_data": {
            "contract": [
                {
                    "parameter": {
                        "value": {
                            "owner_address": FROM_ADDR_RAW,
                            "contract_address": TRC20_CONTRACT_RAW,
                            "data": "a9059cbb0000000000000000000000003c9b65b212316904572826240224750eccce29a20000000000000000000000000000000000000000000000000000000000000001",  # noqa: E501
                            "call_token_value": 0,
                            "call_value": 0,
                            "token_id": 0,
                        },
                        "type_url": "type.googleapis.com/protocol.TriggerSmartContract",
                    },
                    "type": "TriggerSmartContract",
                }
            ],
            "timestamp": 1751554232807,
            "expiration": 1751554292807,
            "ref_block_bytes": REF_BLOCK_BYTES,
            "ref_block_hash": REF_BLOCK_HASH,
            "fee_limit": 50000000,
        },
        "signature": [],
        "permission": None,
    }


@pytest.mark.skipif(not protobuf_installed, reason="Protobuf not installed")
@freezegun.freeze_time(datetime.datetime(2025, 7, 13, 10, 30, 0, 0, tzinfo=datetime.timezone.utc))
def test_offline_transaction_fields_vs_online() -> None:
    client = Tron(network="nile")
    with patch.object(client, "get_latest_solid_block_id", return_value=REF_BLOCK_ID):
        online_json = client.trx.transfer(FROM_ADDR, TO_ADDR, 1).build().to_json()
    offline_json = client.trx.transfer(FROM_ADDR, TO_ADDR, 1).build(offline=True, ref_block_id=REF_BLOCK_ID).to_json()
    assert offline_json["permission"] is None
    assert online_json == offline_json
    with pytest.raises(ValueError, match="ref_block_id is required"):
        client.trx.transfer(FROM_ADDR, TO_ADDR, 1).build(offline=True)


@pytest.mark.skipif(not protobuf_installed, reason="Protobuf not installed")
@freezegun.freeze_time(datetime.datetime(2025, 7, 13, 10, 30, 0, 0, tzinfo=datetime.timezone.utc))
def test_offline_smart_contract_transaction_fields_vs_online() -> None:
    client = Tron(network="nile")
    contract = client.get_contract(TRC20_CONTRACT)
    with patch.object(client, "get_latest_solid_block_id", return_value=REF_BLOCK_ID):
        online_json = (
            contract.functions.transfer(TO_ADDR, 1_000).with_owner(FROM_ADDR).fee_limit(5_000_000).build()
        ).to_json()
    offline_json = (
        contract.functions.transfer(TO_ADDR, 1_000)
        .with_owner(FROM_ADDR)
        .fee_limit(5_000_000)
        .build(offline=True, ref_block_id=REF_BLOCK_ID)
        .to_json()
    )
    assert offline_json["permission"] is None
    assert online_json == offline_json
