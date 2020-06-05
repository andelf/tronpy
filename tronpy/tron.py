from typing import Union
import time
import requests
from pprint import pprint

from tronpy import keys
from tronpy.keys import PrivateKey

TAddress = Union[str, bytes]


def current_timestamp() -> int:
    return int(time.time() * 1000)


class Transaction(object):
    def __init__(self, raw_data: dict):
        self._raw_data = raw_data
        self._signature = []

        super().__init__()

    def inspect(self) -> 'Transaction':
        pprint({"raw_data": self._raw_data, "signature": self._signature})
        return self

    def sign(self, priv_key: PrivateKey) -> 'Transaction':
        return self

    def broadcast(self):
        pass


class TransactionBuilder(object):
    def __init__(self, inner: dict):
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
        return Transaction(self._raw_data)


class Trx(object):
    """The Trx(transaction) API"""

    def _build_inner_transaction(self, type_: str, obj: dict) -> dict:
        return {
            "parameter": {"value": obj, "type_url": "type.googleapis.com/protocol.{}".format(type_),},
            "type": type_,
        }

    def transfer(self, from_: TAddress, to: TAddress, amount: int) -> TransactionBuilder:
        inner = self._build_inner_transaction(
            "TransferContract",
            {"owner_address": keys.to_hex_address(from_), "to_address": keys.to_hex_address(to), "amount": amount,},
        )
        return TransactionBuilder(inner)


class Tron(object):

    # Address API
    is_address = staticmethod(keys.is_address)
    is_base58check_address = staticmethod(keys.is_base58check_address)
    is_hex_address = staticmethod(keys.is_hex_address)

    to_base58chck_address = staticmethod(keys.to_base58check_address)
    to_hex_address = staticmethod(keys.to_hex_address)

    def __init__(self, network="mainnet", private_key=None):

        self._trx = Trx()

        super().__init__()

    @property
    def trx(self):
        return self._trx

    def get_latest_solid_block(self) -> dict:
        url = 'https://api.trongrid.io/walletsolidity/getnowblock'
        block = requests.get(url).json()

        return block
