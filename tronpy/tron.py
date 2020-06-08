from typing import Union
import time
import requests
from pprint import pprint
import json

from tronpy import keys
from tronpy.keys import PrivateKey
from tronpy.exceptions import (
    BadSignature,
    BadKey,
    TaposError,
    UnknownError,
    TransactionError,
    ValidationError,
    ApiError,
    AddressNotFound,
)

TAddress = Union[str, bytes]


FULL_NODE_API_URL = 'https://api.shasta.trongrid.io'
# FULL_NODE_API_URL = 'https://api.nileex.io'
FULL_NODE_API_URL = 'https://api.trongrid.io'


def current_timestamp() -> int:
    return int(time.time() * 1000)


class TransactionRet(dict):
    pass


class Transaction(object):
    def __init__(self, raw_data: dict, client: 'Tron' = None):
        self._raw_data = raw_data
        self._signature = []
        self._client = client
        self.txid = ''
        self._permission = None

        super().__init__()

        sign_weight = self._client.get_sign_weight(self)
        if 'transaction' not in sign_weight:
            self._client._handle_api_error(sign_weight)
            return  # unreachable

        self.txid = sign_weight['transaction']['transaction']['txID']
        # when account not exist on-chain
        self._permission = sign_weight.get('permission', None)

    def to_json(self) -> dict:
        return {'txID': self.txid, 'raw_data': self._raw_data, 'signature': self._signature}

    def inspect(self) -> 'Transaction':
        pprint(self.to_json())
        return self

    def sign(self, priv_key: PrivateKey) -> 'Transaction':
        assert self.txid, "txID not calculated"

        if self._permission is not None:
            addr_of_key = priv_key.public_key.to_hex_address()
            for key in self._permission['keys']:
                if key['address'] == addr_of_key:
                    break
            else:
                raise BadKey(
                    "provided private key is not in the permission list",
                    'provided {}'.format(priv_key.public_key.to_base58check_address()),
                    'required {}'.format(self._permission),
                )
        sig = priv_key.sign_msg_hash(bytes.fromhex(self.txid))
        self._signature.append(sig.hex())
        return self

    def broadcast(self):
        return self._client.broadcast(self)

    def __str__(self):
        return json.dumps(self.to_json(), indent=2)


class TransactionBuilder(object):
    def __init__(self, inner: dict, client: 'Tron'):
        self._client = client
        self._raw_data = {
            'contract': [inner],
            'timestamp': current_timestamp(),
            'expiration': current_timestamp() + 60_000,
            'ref_block_bytes': None,
            'ref_block_hash': None,
        }

        super().__init__()

    def permission_id(self, perm_id: int) -> 'TransactionBuilder':
        self._raw_data['contract'][0]['Permission_id'] = perm_id
        return self

    def memo(self, memo: Union[str, bytes]) -> 'TransactionBuilder':
        data = memo.encode() if isinstance(memo, (str,)) else memo
        self._raw_data['data'] = data.hex()
        return self

    def fee_limit(self, value: int) -> 'TransactionBuilder':
        self._raw_data['fee_limit'] = value
        return self

    def build(self, options=None, **kwargs) -> Transaction:
        ref_block_id = self._client.get_latest_solid_block_id()
        # last 2 byte of block number part
        self._raw_data['ref_block_bytes'] = ref_block_id[12:16]
        # last half part of block hash
        self._raw_data['ref_block_hash'] = ref_block_id[16:32]

        txn = Transaction(self._raw_data, client=self._client)
        return txn


class Trx(object):
    """The Trx(transaction) API"""

    def __init__(self, tron):
        self._tron = tron

    @property
    def client(self) -> 'Tron':
        return self._tron

    def _build_inner_transaction(self, type_: str, obj: dict) -> dict:
        return {
            "parameter": {"value": obj, "type_url": "type.googleapis.com/protocol.{}".format(type_)},
            "type": type_,
        }

    def transfer(self, from_: TAddress, to: TAddress, amount: int) -> TransactionBuilder:
        inner = self._build_inner_transaction(
            "TransferContract",
            {"owner_address": keys.to_hex_address(from_), "to_address": keys.to_hex_address(to), "amount": amount},
        )
        return TransactionBuilder(inner, client=self.client)

    def asset_transfer(self, from_: TAddress, to: TAddress, amount: int, token_id: int) -> TransactionBuilder:
        inner = self._build_inner_transaction(
            "TransferAssetContract",
            {
                "owner_address": keys.to_hex_address(from_),
                "to_address": keys.to_hex_address(to),
                "amount": amount,
                "asset_name": str(token_id).encode().hex(),
            },
        )
        return TransactionBuilder(inner, client=self.client)

    def asset_issue(
        self,
        owner: TAddress,
        abbr: str,
        total_supply: int,
        *,
        url: str,
        name: str = None,
        description: str = '',
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

        inner = self._build_inner_transaction(
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
        return TransactionBuilder(inner, client=self.client)


class Tron(object):

    # Address API
    is_address = staticmethod(keys.is_address)
    is_base58check_address = staticmethod(keys.is_base58check_address)
    is_hex_address = staticmethod(keys.is_hex_address)

    to_base58chck_address = staticmethod(keys.to_base58check_address)
    to_hex_address = staticmethod(keys.to_hex_address)

    def __init__(self, network="mainnet", private_key=None):

        super().__init__()

        self._trx = Trx(self)

    @property
    def trx(self):
        return self._trx

    def get_latest_solid_block(self) -> dict:
        url = FULL_NODE_API_URL + '/walletsolidity/getnowblock'
        resp = requests.get(url)
        block = resp.json()

        return block

    def get_latest_solid_block_id(self) -> str:
        url = FULL_NODE_API_URL + '/wallet/getnodeinfo'
        resp = requests.get(url)
        node_info = resp.json()

        return node_info["solidityBlock"].split(',ID:', 1)[-1]

    def broadcast(self, txn: Transaction):
        url = FULL_NODE_API_URL + '/wallet/broadcasttransaction'
        resp = requests.post(url, json=txn.to_json())
        paylaod = resp.json()
        self._handle_api_error(paylaod)
        return paylaod

    def get_sign_weight(self, txn: TransactionBuilder) -> str:
        url = FULL_NODE_API_URL + '/wallet/getsignweight'
        resp = requests.post(url, json=txn.to_json())
        return resp.json()

    def get_account(self, addr: TAddress) -> dict:
        url = FULL_NODE_API_URL + '/wallet/getaccount'
        resp = requests.post(url, json={"address": keys.to_base58check_address(addr), "visible": True})
        ret = resp.json()
        if ret:
            return ret
        else:
            raise AddressNotFound("account not found on-chain")

    def get_account_resource(self, addr: TAddress):
        url = FULL_NODE_API_URL + '/wallet/getaccountresource'
        resp = requests.post(url, json={"address": keys.to_base58check_address(addr), "visible": True})
        return resp.json()

    def get_account_permission(self, addr: TAddress) -> dict:
        addr = keys.to_base58check_address(addr)
        # will check account existence
        info = self.get_account(addr)
        # For old accounts prior to AccountPermissionUpdate, these fields are not set.
        # So default permission is for backward compatibility.
        default_witness = None
        if info.get('is_witness', None):
            default_witness = {
                'type': 'Witness',
                'id': 1,
                'permission_name': 'witness',
                'threshold': 1,
                'keys': [{'address': addr, 'weight': 1}],
            }
        return {
            'owner': info.get(
                'owner_permission',
                {'permission_name': 'owner', 'threshold': 1, 'keys': [{'address': addr, 'weight': 1}]},
            ),
            'actives': info.get(
                'active_permission',
                [
                    {
                        'type': 'Active',
                        'id': 2,
                        'permission_name': 'active',
                        'threshold': 1,
                        'operations': '7fff1fc0033e0100000000000000000000000000000000000000000000000000',
                        'keys': [{'address': addr, 'weight': 1}],
                    }
                ],
            ),
            'witness': info.get('witness_permission', default_witness),
        }

    def _handle_api_error(self, payload: dict):
        if payload.get('result', None):
            return
        if 'Error' in payload:
            # class java.lang.NullPointerException : null
            raise ApiError(payload['Error'])
        if 'code' in payload:
            if payload['code'] == 'SIGERROR':
                raise BadSignature(bytes.fromhex(payload['message']).decode())
            elif payload['code'] == 'TAPOS_ERROR':
                raise TaposError(bytes.fromhex(payload['message']).decode())
            elif payload['code'] in ['TRANSACTION_EXPIRATION_ERROR', 'TOO_BIG_TRANSACTION_ERROR']:
                raise TransactionError(bytes.fromhex(payload['message']).decode())
            elif payload['code'] == 'CONTRACT_VALIDATE_ERROR':
                raise ValidationError(bytes.fromhex(payload['message']).decode())
            raise UnknownError(payload)
