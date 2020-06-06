from typing import Union
import time
import requests
from pprint import pprint

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
)

TAddress = Union[str, bytes]


FULL_NODE_API_URL = 'https://api.shasta.trongrid.io'


def current_timestamp() -> int:
    return int(time.time() * 1000)


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
