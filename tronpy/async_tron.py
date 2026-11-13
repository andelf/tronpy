"""Old names kept for compatibility. Use the names from `tronpy.tron` instead."""

from tronpy.contract import Contract as AsyncContract
from tronpy.contract import ContractMethod as AsyncContractMethod
from tronpy.contract import ShieldedTRC20 as AsyncShieldedTRC20
from tronpy.providers.http import HTTPProvider as AsyncHTTPProvider
from tronpy.tron import Transaction as AsyncTransaction
from tronpy.tron import TransactionBuilder as AsyncTransactionBuilder
from tronpy.tron import TransactionRet as AsyncTransactionRet
from tronpy.tron import Tron as AsyncTron
from tronpy.tron import Trx as AsyncTrx

__all__ = [
    "AsyncContract",
    "AsyncContractMethod",
    "AsyncHTTPProvider",
    "AsyncShieldedTRC20",
    "AsyncTransaction",
    "AsyncTransactionBuilder",
    "AsyncTransactionRet",
    "AsyncTron",
    "AsyncTrx",
]
