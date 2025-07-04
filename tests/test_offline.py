import datetime
import typing

import freezegun
import pytest

from tronpy.async_tron import AsyncTransaction
from tronpy.tron import Transaction


@pytest.mark.parametrize("transaction", [Transaction, AsyncTransaction])
@freezegun.freeze_time(datetime.datetime(2025, 7, 2, 14, 27, 12, 131000, tzinfo=datetime.timezone.utc))
def test_create_transaction_offline(transaction: typing.Union[Transaction, AsyncTransaction]) -> None:
    owner_address = "TSJAbe7YTH6xfFiZHkv5bzXTQ5uDqz9eW8"
    to_address = "TQGjrFjwuXuQu7ZhxcVeqpDVxFZt9RgzUs"
    amount = 1_000_000
    ref_block_id = "0000000003546431212a13dbe72ac5c09a684deb83257258a6fcdc1115835077"

    transaction = transaction.build_offline(
        owner_address=owner_address,
        to_address=to_address,
        amount=amount,
        ref_block_id=ref_block_id,
    )

    assert transaction.to_json() == {
        "txID": "365366f9dd5e39ecc85a524c7c43757f3abdf5433d3b80e5b6645a3dbd19dfe7",
        "raw_data": {
            "contract": [
                {
                    "parameter": {
                        "value": {
                            "owner_address": "41b317e8c4d4405459663d5f55b0bbb5ef3b4aa76d",
                            "to_address": "419ce29546a328107df7b685ed3183fa8ae70a46a7",
                            "amount": 1000000,
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


@pytest.mark.parametrize("transaction", [Transaction, AsyncTransaction])
@freezegun.freeze_time(datetime.datetime(2025, 7, 3, 14, 50, 32, 807000, tzinfo=datetime.timezone.utc))
def test_create_smart_contract_transaction_offline(transaction: typing.Union[Transaction, AsyncTransaction]) -> None:
    contract_address = "TGaVEQQABuvKMbmThCsS9w27J4K5MuMJCF"
    owner_address = "TSJAbe7YTH6xfFiZHkv5bzXTQ5uDqz9eW8"
    address_to = "TQGjrFjwuXuQu7ZhxcVeqpDVxFZt9RgzUs"
    ref_block_id = "000000000354d55ee2d2fa09a1af9a14673b2160c7e75f7afcdca3f37a24b251"
    amount = 1_000_000
    fee_limit = 50000000

    transaction = transaction.build_trc20_transfer_offline(
        from_address=owner_address,
        to_address=address_to,
        amount=amount,
        contract_address=contract_address,
        ref_block_id=ref_block_id,
        fee_limit=fee_limit,
    )

    assert transaction.to_json() == {
        "txID": "1c8748aa063eca333fb387b04402cc83763b59f0f21260791b628d299d3e02d1",
        "raw_data": {
            "contract": [
                {
                    "parameter": {
                        "value": {
                            "owner_address": "41b317e8c4d4405459663d5f55b0bbb5ef3b4aa76d",
                            "contract_address": "41487cdc8f5e2064cfe2bcf42d58bc818639cbdf95",
                            "data": "a9059cbb0000000000000000000000009ce29546a328107df7b685ed3183fa8ae70a46a700000000000000000000000000000000000000000000000000000000000f4240",  # noqa: E501
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
            "ref_block_bytes": "d55e",
            "ref_block_hash": "e2d2fa09a1af9a14",
            "fee_limit": 50000000,
        },
        "signature": [],
        "permission": None,
    }
