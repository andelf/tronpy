import datetime
import importlib
import typing
from unittest.mock import AsyncMock, patch

import freezegun
import pytest

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
    yield
    importlib.import_module("tronpy.tron").proto = proto


@pytest.mark.usefixtures("set_protobuf_unavailable")
@pytest.mark.asyncio
async def test_offline_transfer_raises_import_error() -> None:
    client = Tron(network="nile")
    with pytest.raises(ImportError) as exc_info:
        await client.trx.transfer(FROM_ADDR, TO_ADDR, 1).build(offline=True, ref_block_id="ref_block_id")
    assert exc_info.value.args[0] == PROTOBUF_NOT_INSTALLED_ERROR_MESSAGE


@pytest.mark.usefixtures("set_protobuf_unavailable")
@pytest.mark.asyncio
async def test_offline_contract_transfer_raises_import_error() -> None:
    async with Tron(network="nile") as client:
        contract = await client.get_contract(TRC20_CONTRACT)
        builder = await contract.functions.transfer(TO_ADDR, 1)
        with pytest.raises(ImportError) as exc_info:
            await builder.with_owner(FROM_ADDR).fee_limit(FEE_LIMIT).build(offline=True, ref_block_id="ref_block_id")
    assert exc_info.value.args[0] == PROTOBUF_NOT_INSTALLED_ERROR_MESSAGE


@pytest.mark.skipif(not protobuf_installed, reason="Protobuf not installed")
@pytest.mark.asyncio
@freezegun.freeze_time(datetime.datetime(2025, 7, 2, 14, 27, 12, 131000, tzinfo=datetime.UTC))
async def test_create_transaction_offline() -> None:
    client = Tron(network="nile")
    transaction = await client.trx.transfer(FROM_ADDR, TO_ADDR, 1).build(offline=True, ref_block_id=REF_BLOCK_ID)
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
        "raw_data_hex": "0a0264312208212a13dbe72ac5c040e381a7dcfc325a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a154194a15629b2b2bbd3a5453e6d6696b2875278633b1215413c9b65b212316904572826240224750eccce29a218017083ada3dcfc32",  # noqa: E501
        "signature": [],
        "permission": None,
    }


@pytest.mark.skipif(not protobuf_installed, reason="Protobuf not installed")
@pytest.mark.asyncio
@freezegun.freeze_time(datetime.datetime(2025, 7, 3, 14, 50, 32, 807000, tzinfo=datetime.UTC))
async def test_create_smart_contract_transaction_offline() -> None:
    async with Tron(network="nile") as client:
        contract = await client.get_contract(TRC20_CONTRACT)
        builder = await contract.functions.transfer(TO_ADDR, 1)
        transaction = await builder.with_owner(FROM_ADDR).fee_limit(FEE_LIMIT).build(offline=True, ref_block_id=REF_BLOCK_ID)
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
        "raw_data_hex": "0a0264312208212a13dbe72ac5c040c7f89586fd325aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a154194a15629b2b2bbd3a5453e6d6696b2875278633b12154154e24764f19b0450d49d4b66270da289666cf82a2244a9059cbb0000000000000000000000003c9b65b212316904572826240224750eccce29a2000000000000000000000000000000000000000000000000000000000000000170e7a39286fd32900180e1eb17",  # noqa: E501
        "signature": [],
        "permission": None,
    }


@pytest.mark.skipif(not protobuf_installed, reason="Protobuf not installed")
@pytest.mark.asyncio
@freezegun.freeze_time(datetime.datetime(2025, 7, 13, 10, 30, 0, 0, tzinfo=datetime.UTC))
async def test_offline_transaction_fields_vs_online() -> None:
    async with Tron(network="nile") as client:
        with patch.object(client, "get_latest_solid_block_id", AsyncMock(return_value=REF_BLOCK_ID)):
            online = await client.trx.transfer(FROM_ADDR, TO_ADDR, 1).build()
        online_json = online.to_json()
        offline = await client.trx.transfer(FROM_ADDR, TO_ADDR, 1).build(offline=True, ref_block_id=REF_BLOCK_ID)
        offline_json = offline.to_json()
        assert offline_json.pop("permission") is None
        online_json.pop("permission")
        assert online_json == offline_json
        with pytest.raises(ValueError, match="ref_block_id is required"):
            await client.trx.transfer(FROM_ADDR, TO_ADDR, 1).build(offline=True)


@pytest.mark.skipif(not protobuf_installed, reason="Protobuf not installed")
@pytest.mark.parametrize(
    "customize",
    [lambda builder: builder.memo("test memo"), lambda builder: builder.permission_id(2)],
    ids=["memo", "permission_id"],
)
@pytest.mark.asyncio
@freezegun.freeze_time(datetime.datetime(2025, 7, 13, 10, 30, 0, 0, tzinfo=datetime.UTC))
async def test_offline_transaction_optional_fields_vs_online(customize: typing.Callable) -> None:
    async with Tron(network="nile") as client:
        with patch.object(client, "get_latest_solid_block_id", AsyncMock(return_value=REF_BLOCK_ID)):
            online = await customize(client.trx.transfer(FROM_ADDR, TO_ADDR, 1)).build()
        offline = await customize(client.trx.transfer(FROM_ADDR, TO_ADDR, 1)).build(offline=True, ref_block_id=REF_BLOCK_ID)
    assert online.txid == offline.txid
    assert online.raw_data_hex == offline.raw_data_hex


@pytest.mark.skipif(not protobuf_installed, reason="Protobuf not installed")
@pytest.mark.asyncio
@freezegun.freeze_time(datetime.datetime(2025, 7, 13, 10, 30, 0, 0, tzinfo=datetime.UTC))
async def test_offline_smart_contract_transaction_fields_vs_online() -> None:
    async with Tron(network="nile") as client:
        contract = await client.get_contract(TRC20_CONTRACT)

        async def builder() -> typing.Any:
            return (await contract.functions.transfer(TO_ADDR, 1_000)).with_owner(FROM_ADDR).fee_limit(5_000_000)

        with patch.object(client, "get_latest_solid_block_id", AsyncMock(return_value=REF_BLOCK_ID)):
            online_json = (await (await builder()).build()).to_json()
        offline_json = (await (await builder()).build(offline=True, ref_block_id=REF_BLOCK_ID)).to_json()
    assert offline_json.pop("permission") is None
    online_json.pop("permission")
    assert online_json == offline_json


@pytest.mark.skipif(not protobuf_installed, reason="Protobuf not installed")
@pytest.mark.asyncio
async def test_offline_transaction_needs_client_to_reach_the_node() -> None:
    async with Tron(network="nile") as client:
        transaction = await client.trx.transfer(FROM_ADDR, TO_ADDR, 1).build(offline=True, ref_block_id=REF_BLOCK_ID)
    with pytest.raises(TypeError, match="transaction has no client"):
        await transaction.broadcast()
    with pytest.raises(TypeError, match="transaction has no client"):
        await transaction.update()
    with pytest.raises(TypeError, match="transaction has no client"):
        await transaction.check_sign_weight()
