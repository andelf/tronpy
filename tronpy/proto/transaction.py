import hashlib
import typing

import google.protobuf.any_pb2

from tronpy.defaults import SIXTY_SECONDS
from tronpy.keys import to_hex_address, to_raw_address
from tronpy.proto.src import tron_pb2
from tronpy.utils import current_timestamp, get_ref_block_bytes, get_ref_block_hash


class Transaction(typing.TypedDict):
    txID: str
    raw_data: typing.Dict[str, typing.Any]
    signature: typing.List[str]
    permission: typing.Optional[typing.Dict[str, typing.Any]]


def calculate_txid(transaction: tron_pb2.Transaction) -> str:
    raw_bytes = transaction.raw_data.SerializeToString()
    return hashlib.sha256(raw_bytes).hexdigest()


# ------------------------------------------------------------------ #
# Helper functions shared by transaction builders                    #
# ------------------------------------------------------------------ #


def _get_tapos_meta(ref_block_id: str) -> typing.Tuple[str, str, int, int]:
    """Extract TAPoS metadata from a block id.

    Parameters
    ----------
    ref_block_id: Hex string of the latest block id

    Returns
    -------
    typing.Tuple[str, str, int, int]
        (ref_block_bytes_hex, ref_block_hash_hex, timestamp_ms, expiration_ms)
    """
    ref_block_bytes_hex = get_ref_block_bytes(ref_block_id)
    ref_block_hash_hex = get_ref_block_hash(ref_block_id)
    timestamp = current_timestamp()
    expiration = timestamp + SIXTY_SECONDS
    return ref_block_bytes_hex, ref_block_hash_hex, timestamp, expiration


def create_transaction_offline(
    owner_address: str,
    to_address: str,
    amount: int,
    ref_block_id: str,
) -> Transaction:
    to_address_raw = to_raw_address(to_address)
    from_address_raw = to_raw_address(owner_address)

    ref_block_bytes_hex, ref_block_hash_hex, timestamp, expiration = _get_tapos_meta(ref_block_id)

    transaction_raw = tron_pb2.Transaction.raw(
        ref_block_bytes=bytes.fromhex(ref_block_bytes_hex),
        ref_block_hash=bytes.fromhex(ref_block_hash_hex),
        expiration=expiration,
        timestamp=timestamp,
        contract=[
            tron_pb2.Transaction.Contract(
                type=tron_pb2.Transaction.Contract.ContractType.TransferContract,
                parameter=google.protobuf.any_pb2.Any(
                    type_url="type.googleapis.com/protocol.TransferContract",
                    value=tron_pb2.TransferContract(
                        owner_address=from_address_raw,
                        to_address=to_address_raw,
                        amount=amount,
                    ).SerializeToString(),
                ),
            ),
        ],
    )

    transaction = tron_pb2.Transaction(raw_data=transaction_raw)
    tx_id = calculate_txid(transaction)

    return {
        "txID": tx_id,
        "raw_data": {
            "ref_block_bytes": ref_block_bytes_hex,
            "ref_block_hash": ref_block_hash_hex,
            "expiration": expiration,
            "timestamp": timestamp,
            "contract": [
                {
                    "type": "TransferContract",
                    "parameter": {
                        "type_url": "type.googleapis.com/protocol.TransferContract",
                        "value": {
                            "owner_address": to_hex_address(owner_address),
                            "to_address": to_hex_address(to_address),
                            "amount": amount,
                        },
                    },
                }
            ],
        },
        "signature": [],
        "permission": None,
    }


def create_smart_contract_transaction_offline(
    from_address: str,
    to_address: str,
    amount: int,
    ref_block_id: str,
    fee_limit: int,
    contract_address: str,
) -> Transaction:
    """Create and sign a TRC-20 `transfer` transaction.

    Parameters
    ----------
    from_address: Base58Check address of the sender
    to_address:   Recipient address (Base58Check or hex)
    amount:       Token amount in the token's smallest unit
    ref_block_id: Hex string of the latest block id (for TAPoS)
    private_key:  32-byte private key of the sender
    fee_limit:    Maximum energy fee to spend (in SUN)
    contract_address: Address of the token (smart-contract) to invoke
    """

    # ------------------------------------------------------------------ #
    # 0.  Address conversions                                            #
    # ------------------------------------------------------------------ #
    from_raw = to_raw_address(from_address)
    contract_raw = to_raw_address(contract_address)

    # ------------------------------------------------------------------ #
    # 1.  Encode `transfer(address,uint256)` call data                    #
    # ------------------------------------------------------------------ #
    # The calldata for an ERC-20 token transfer is constructed per the
    # Ethereum Contract ABI specification:
    #   https://docs.soliditylang.org/en/latest/abi-spec.html
    #
    #  • First 4 bytes – function selector: keccak256("transfer(address,uint256)")
    #    → 0xa9059cbb.
    #  • Each argument is a 32-byte word, left-padded with zeros.
    #      * `address` (20 bytes) – we drop Tron’s 0x41 prefix to obtain the raw
    #        EVM address, then left-pad to 32 bytes.
    #      * `uint256 amount` – encoded as big-endian hex and left-padded.
    #
    # Good walk-throughs:
    #   RareSkills – Understanding ABI Encoding:
    #     https://www.rareskills.io/post/abi-encoding
    #   QuickNode – Transaction Calldata Demystified:
    #     https://www.quicknode.com/guides/ethereum-development/transactions/ethereum-transaction-calldata
    to_hex = to_hex_address(to_address)
    # Remove the 0x41 prefix (1-byte Tron address prefix) → 20-byte EVM
    to_evm = to_hex[2:]
    to_padded = to_evm.rjust(64, "0")
    amount_hex = hex(amount)[2:].rjust(64, "0")
    data_hex = "a9059cbb" + to_padded + amount_hex  # 4-byte selector + args
    data_bytes = bytes.fromhex(data_hex)

    # ------------------------------------------------------------------ #
    # 2.  TAPoS metadata                                                 #
    # ------------------------------------------------------------------ #
    ref_block_bytes_hex, ref_block_hash_hex, timestamp, expiration = _get_tapos_meta(ref_block_id)

    # ------------------------------------------------------------------ #
    # 3.  Build proto.Transaction                                        #
    # ------------------------------------------------------------------ #
    transaction_raw = tron_pb2.Transaction.raw(
        ref_block_bytes=bytes.fromhex(ref_block_bytes_hex),
        ref_block_hash=bytes.fromhex(ref_block_hash_hex),
        expiration=expiration,
        timestamp=timestamp,
        fee_limit=fee_limit,
        contract=[
            tron_pb2.Transaction.Contract(
                type=tron_pb2.Transaction.Contract.ContractType.TriggerSmartContract,
                parameter=google.protobuf.any_pb2.Any(
                    type_url="type.googleapis.com/protocol.TriggerSmartContract",
                    value=tron_pb2.TriggerSmartContract(
                        owner_address=from_raw,
                        contract_address=contract_raw,
                        data=data_bytes,
                        call_value=0,  # no TRX transferred in a token tx
                        call_token_value=0,
                        token_id=0,
                    ).SerializeToString(),
                ),
            )
        ],
    )

    # ------------------------------------------------------------------ #
    # 4.  Get transaction id                                             #
    # ------------------------------------------------------------------ #
    transaction = tron_pb2.Transaction(raw_data=transaction_raw)
    tx_id = calculate_txid(transaction)

    # ------------------------------------------------------------------ #
    # 5.  Return simplified JSON-style dict                              #
    # ------------------------------------------------------------------ #
    return {
        "txID": tx_id,
        "raw_data": {
            "ref_block_bytes": ref_block_bytes_hex,
            "ref_block_hash": ref_block_hash_hex,
            "expiration": expiration,
            "timestamp": timestamp,
            "fee_limit": fee_limit,
            "contract": [
                {
                    "type": "TriggerSmartContract",
                    "parameter": {
                        "type_url": "type.googleapis.com/protocol.TriggerSmartContract",
                        "value": {
                            "owner_address": to_hex_address(from_address),
                            "contract_address": to_hex_address(contract_address),
                            "data": data_hex,
                            "call_value": 0,
                            "call_token_value": 0,
                            "token_id": 0,
                        },
                    },
                }
            ],
        },
        "signature": [],
        "permission": None,
    }
