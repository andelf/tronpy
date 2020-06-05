from typing import Union

from tronpy import keys

AddressT = Union[str, bytes]


class Transaction(object):
    def broadcast(self):
        pass


class TransactionBuilder(object):
    def build(self, options=None, **kwargs) -> Transaction:
        pass


class Trx(object):
    """The Trx API"""

    def transfer(self, from_: AddressT, to: AddressT, amount: int) -> TransactionBuilder:
        return TransactionBuilder()


class Tron(object):

    # Address API
    is_address = staticmethod(keys.is_address)
    is_base58check_address = staticmethod(keys.is_base58check_address)
    is_hex_address = staticmethod(keys.is_hex_address)

    to_base58chck_address = staticmethod(keys.to_base58check_address)

    def __init__(self, network="mainnet", private_key=None):

        self._trx = Trx()

        super().__init__()

    @property
    def trx(self):
        return self._trx
