import hashlib
from typing import Any

from tronpy.exceptions import ProtobufImportError
from tronpy.keys import to_raw_address

try:
    import google.protobuf.any_pb2

    from tronpy.proto import tron_pb2
except ImportError as exc:
    raise ProtobufImportError from exc


def calculate_txid_from_raw_data(raw_data: dict[str, Any]) -> str:
    """Calculate txid using protobuf serialization"""
    transaction_raw = _raw_data_to_protobuf(raw_data)
    transaction = tron_pb2.Transaction(raw_data=transaction_raw)
    raw_bytes = transaction.raw_data.SerializeToString()
    return hashlib.sha256(raw_bytes).hexdigest()


def _raw_data_to_protobuf(raw_data: dict[str, Any]):
    """Convert raw_data dictionary to protobuf Transaction.raw format."""
    contracts = []
    for contract_data in raw_data["contract"]:
        contract_type = contract_data["type"]
        contract_params = contract_data["parameter"]["value"]
        if contract_type == "TransferContract":
            contract_proto = tron_pb2.TransferContract(
                owner_address=to_raw_address(contract_params["owner_address"]),
                to_address=to_raw_address(contract_params["to_address"]),
                amount=contract_params["amount"],
            )
        elif contract_type == "TriggerSmartContract":
            contract_proto = tron_pb2.TriggerSmartContract(
                owner_address=to_raw_address(contract_params["owner_address"]),
                contract_address=to_raw_address(contract_params["contract_address"]),
                data=bytes.fromhex(contract_params["data"]),
                call_value=contract_params.get("call_value", 0),
                call_token_value=contract_params.get("call_token_value", 0),
                token_id=contract_params.get("token_id", 0),
            )
        else:
            raise ValueError(f"Unsupported contract type: {contract_type}")
        contract = tron_pb2.Transaction.Contract(
            type=getattr(tron_pb2.Transaction.Contract.ContractType, contract_type),
            parameter=google.protobuf.any_pb2.Any(
                type_url=contract_data["parameter"]["type_url"],
                value=contract_proto.SerializeToString(),
            ),
        )
        contracts.append(contract)
    transaction_raw = tron_pb2.Transaction.raw(
        ref_block_bytes=bytes.fromhex(raw_data["ref_block_bytes"]),
        ref_block_hash=bytes.fromhex(raw_data["ref_block_hash"]),
        expiration=raw_data["expiration"],
        timestamp=raw_data["timestamp"],
        contract=contracts,
    )
    if "fee_limit" in raw_data:
        transaction_raw.fee_limit = raw_data["fee_limit"]
    return transaction_raw
