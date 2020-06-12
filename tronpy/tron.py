from typing import Union
import time
import requests
from pprint import pprint
import json
from decimal import Decimal
from urllib.parse import urljoin

from tronpy import keys
from tronpy.contract import Contract
from tronpy.keys import PrivateKey
from tronpy.providers import HTTPProvider
from tronpy.defaults import conf_for_name
from tronpy.exceptions import (
    BadSignature,
    BadKey,
    BadHash,
    TaposError,
    UnknownError,
    TransactionError,
    ValidationError,
    ApiError,
    AddressNotFound,
    TransactionNotFound,
)

TAddress = Union[str, bytes]


FULL_NODE_API_URL = "https://api.shasta.trongrid.io"
FULL_NODE_API_URL = "https://api.nileex.io"
# FULL_NODE_API_URL = "https://api.trongrid.io"


def current_timestamp() -> int:
    return int(time.time() * 1000)


class TransactionRet(dict):
    def __init__(self, iterable, client: "Tron"):
        super().__init__(iterable)

        self._client = client
        self._txid = self["txid"]

    def wait(self, timeout=0, interval=1.6) -> dict:
        end_time = time.time() + timeout * 1_0000
        while time.time() < end_time:
            try:
                return self._client.get_transaction_info(self._txid)
            except TransactionNotFound:
                time.sleep(interval)

        raise TransactionNotFound("timeout and can not find the transaction")


class Transaction(object):
    def __init__(self, raw_data: dict, client: "Tron" = None):
        self._raw_data = raw_data
        self._signature = []
        self._client = client
        self.txid = ""
        self._permission = None

        super().__init__()

        sign_weight = self._client.get_sign_weight(self)
        if "transaction" not in sign_weight:
            self._client._handle_api_error(sign_weight)
            return  # unreachable

        self.txid = sign_weight["transaction"]["transaction"]["txID"]
        # when account not exist on-chain
        self._permission = sign_weight.get("permission", None)

    def to_json(self) -> dict:
        return {"txID": self.txid, "raw_data": self._raw_data, "signature": self._signature}

    def inspect(self) -> "Transaction":
        pprint(self.to_json())
        return self

    def sign(self, priv_key: PrivateKey) -> "Transaction":
        assert self.txid, "txID not calculated"

        if self._permission is not None:
            addr_of_key = priv_key.public_key.to_hex_address()
            for key in self._permission["keys"]:
                if key["address"] == addr_of_key:
                    break
            else:
                raise BadKey(
                    "provided private key is not in the permission list",
                    "provided {}".format(priv_key.public_key.to_base58check_address()),
                    "required {}".format(self._permission),
                )
        sig = priv_key.sign_msg_hash(bytes.fromhex(self.txid))
        self._signature.append(sig.hex())
        return self

    def broadcast(self) -> TransactionRet:
        return TransactionRet(self._client.broadcast(self), client=self._client)

    def __str__(self):
        return json.dumps(self.to_json(), indent=2)


class TransactionBuilder(object):
    def __init__(self, inner: dict, client: "Tron", contract: Contract = None):
        self._client = client
        self._raw_data = {
            "contract": [inner],
            "timestamp": current_timestamp(),
            "expiration": current_timestamp() + 60_000,
            "ref_block_bytes": None,
            "ref_block_hash": None,
        }
        self._contract = contract

        super().__init__()

    def permission_id(self, perm_id: int) -> "TransactionBuilder":
        self._raw_data["contract"][0]["Permission_id"] = perm_id
        return self

    def memo(self, memo: Union[str, bytes]) -> "TransactionBuilder":
        data = memo.encode() if isinstance(memo, (str,)) else memo
        self._raw_data["data"] = data.hex()
        return self

    def fee_limit(self, value: int) -> "TransactionBuilder":
        self._raw_data["fee_limit"] = value
        return self

    def build(self, options=None, **kwargs) -> Transaction:
        ref_block_id = self._client.get_latest_solid_block_id()
        # last 2 byte of block number part
        self._raw_data["ref_block_bytes"] = ref_block_id[12:16]
        # last half part of block hash
        self._raw_data["ref_block_hash"] = ref_block_id[16:32]

        txn = Transaction(self._raw_data, client=self._client)
        return txn


class Trx(object):
    """The Trx(transaction) API"""

    def __init__(self, tron):
        self._tron = tron

    @property
    def client(self) -> "Tron":
        return self._tron

    def _build_transaction(self, type_: str, obj: dict, contract: Contract = None) -> dict:
        inner = {
            "parameter": {"value": obj, "type_url": "type.googleapis.com/protocol.{}".format(type_)},
            "type": type_,
        }
        return TransactionBuilder(inner, client=self.client)

    def transfer(self, from_: TAddress, to: TAddress, amount: int) -> TransactionBuilder:
        return self._build_transaction(
            "TransferContract",
            {"owner_address": keys.to_hex_address(from_), "to_address": keys.to_hex_address(to), "amount": amount},
        )

    def asset_transfer(self, from_: TAddress, to: TAddress, amount: int, token_id: int) -> TransactionBuilder:
        return self._build_transaction(
            "TransferAssetContract",
            {
                "owner_address": keys.to_hex_address(from_),
                "to_address": keys.to_hex_address(to),
                "amount": amount,
                "asset_name": str(token_id).encode().hex(),
            },
        )

    def asset_issue(
        self,
        owner: TAddress,
        abbr: str,
        total_supply: int,
        *,
        url: str,
        name: str = None,
        description: str = "",
        start_time: int = None,
        end_time: int = None,
        precision: int = 6,
        frozen_supply: list = None,
        trx_num: int = 1,
        num: int = 1,
    ) -> TransactionBuilder:
        if name is None:
            name = abbr

        if start_time is None:
            # use default expiration
            start_time = current_timestamp() + 60_000

        if end_time is None:
            # use default expiration
            end_time = current_timestamp() + 60_000 + 1

        if frozen_supply is None:
            frozen_supply = []

        return self._build_transaction(
            "AssetIssueContract",
            {
                "owner_address": keys.to_hex_address(owner),
                "abbr": abbr.encode().hex(),
                "name": name.encode().hex(),
                "total_supply": total_supply,
                "precision": precision,
                "url": url.encode().hex(),
                "description": description.encode().hex(),
                "start_time": start_time,
                "end_time": end_time,
                "frozen_supply": frozen_supply,
                "trx_num": trx_num,
                "num": num,
                "public_free_asset_net_limit": 0,
                "free_asset_net_limit": 0,
            },
        )


class Tron(object):
    # Address API
    is_address = staticmethod(keys.is_address)
    is_base58check_address = staticmethod(keys.is_base58check_address)
    is_hex_address = staticmethod(keys.is_hex_address)

    to_base58check_address = staticmethod(keys.to_base58check_address)
    to_hex_address = staticmethod(keys.to_hex_address)
    to_canonical_address = staticmethod(keys.to_base58check_address)

    def __init__(self, provider: HTTPProvider = None, network: str = "mainnet"):

        self._trx = Trx(self)
        if provider is None:
            self.provider = HTTPProvider(conf_for_name(network))
        else:
            self.provider = provider

    @property
    def trx(self):
        return self._trx

    def _handle_api_error(self, payload: dict):
        if payload.get("result", None) is True:
            return
        if "Error" in payload:
            # class java.lang.NullPointerException : null
            raise ApiError(payload["Error"])
        if "code" in payload:
            try:
                msg = bytes.fromhex(payload["message"]).decode()
            except Exception:
                pass
            finally:
                msg = payload["message"]
            if payload["code"] == "SIGERROR":
                raise BadSignature(msg)
            elif payload["code"] == "TAPOS_ERROR":
                raise TaposError(msg)
            elif payload["code"] in ["TRANSACTION_EXPIRATION_ERROR", "TOO_BIG_TRANSACTION_ERROR"]:
                raise TransactionError(msg)
            elif payload["code"] == "CONTRACT_VALIDATE_ERROR":
                raise ValidationError(msg)
            raise UnknownError(msg, payload["code"])
        if "result" in payload:
            return self._handle_api_error(payload["result"])

    def get_latest_solid_block(self) -> dict:
        block = self.provider.make_request('walletsolidity/getnowblock')
        return block

    def get_latest_solid_block_id(self) -> str:
        info = self.provider.make_request('wallet/getnodeinfo')
        return info["solidityBlock"].split(",ID:", 1)[-1]

    def broadcast(self, txn: Transaction):
        paylaod = self.provider.make_request("/wallet/broadcasttransaction", txn.to_json())
        self._handle_api_error(paylaod)
        return paylaod

    def get_sign_weight(self, txn: TransactionBuilder) -> str:
        url = FULL_NODE_API_URL + "/wallet/getsignweight"
        resp = requests.post(url, json=txn.to_json())
        return resp.json()

    def get_account(self, addr: TAddress) -> dict:
        url = FULL_NODE_API_URL + "/wallet/getaccount"
        resp = requests.post(url, json={"address": keys.to_base58check_address(addr), "visible": True})
        ret = resp.json()
        if ret:
            return ret
        else:
            raise AddressNotFound("account not found on-chain")

    def get_account_resource(self, addr: TAddress) -> dict:
        url = FULL_NODE_API_URL + "/wallet/getaccountresource"
        resp = requests.post(url, json={"address": keys.to_base58check_address(addr), "visible": True})
        return resp.json()

    def get_account_balance(self, addr: TAddress) -> Decimal:
        info = self.get_account(addr)
        return Decimal(info.get("balance")) / 1_000_000

    def get_account_permission(self, addr: TAddress) -> dict:
        addr = keys.to_base58check_address(addr)
        # will check account existence
        info = self.get_account(addr)
        # For old accounts prior to AccountPermissionUpdate, these fields are not set.
        # So default permission is for backward compatibility.
        default_witness = None
        if info.get("is_witness", None):
            default_witness = {
                "type": "Witness",
                "id": 1,
                "permission_name": "witness",
                "threshold": 1,
                "keys": [{"address": addr, "weight": 1}],
            }
        return {
            "owner": info.get(
                "owner_permission",
                {"permission_name": "owner", "threshold": 1, "keys": [{"address": addr, "weight": 1}],},
            ),
            "actives": info.get(
                "active_permission",
                [
                    {
                        "type": "Active",
                        "id": 2,
                        "permission_name": "active",
                        "threshold": 1,
                        "operations": "7fff1fc0033e0100000000000000000000000000000000000000000000000000",
                        "keys": [{"address": addr, "weight": 1}],
                    }
                ],
            ),
            "witness": info.get("witness_permission", default_witness),
        }

    def get_contract(self, addr: TAddress):
        addr = keys.to_base58check_address(addr)
        info = self.provider.make_request('wallet/getcontract', {"value": addr, "visible": True})

        try:
            self._handle_api_error(info)
        except ApiError:
            # your java's null pointer exception sucks
            raise AddressNotFound("contract address not found")

        cntr = Contract(
            addr=addr,
            bytecode=info["bytecode"],
            name=info.get("name", ""),
            abi=info["abi"].get("entrys", []),
            origin_energy_limit=info.get("origin_energy_limit", 0),
            user_resource_percent=info["consume_user_resource_percent"],
            client=self,
        )
        return cntr

    def get_transaction_info(self, txn_id: str) -> dict:
        if len(txn_id) != 64:
            raise BadHash("wrong transaction hash length")

        ret = self.provider.make_request('wallet/gettransactioninfobyid', {"value": txn_id, "visible": True})
        self._handle_api_error(ret)
        if ret:
            return ret
        raise TransactionNotFound

    def trigger_const_smart_contract_function(
        self, owner_address: TAddress, contract_address: TAddress, function_selector: str, parameter: str,
    ) -> str:
        ret = self.provider.make_request(
            'wallet/triggerconstantcontract',
            {
                "owner_address": keys.to_base58check_address(owner_address),
                "contract_address": keys.to_base58check_address(contract_address),
                "function_selector": function_selector,
                "parameter": parameter,
                "visible": True,
            },
        )
        self._handle_api_error(ret)
        return ret["constant_result"][0]
