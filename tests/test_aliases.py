from tronpy import AsyncContract, AsyncTron, Contract, ShieldedTRC20, Tron
from tronpy.async_contract import AsyncContract as ContractModuleAsyncContract
from tronpy.async_contract import AsyncContractFunctions, AsyncContractMethod, AsyncShieldedTRC20
from tronpy.async_tron import AsyncContract as TronModuleAsyncContract
from tronpy.async_tron import AsyncContractMethod as TronModuleAsyncContractMethod
from tronpy.async_tron import (
    AsyncHTTPProvider,
    AsyncTransaction,
    AsyncTransactionBuilder,
    AsyncTransactionRet,
    AsyncTrx,
)
from tronpy.async_tron import AsyncShieldedTRC20 as TronModuleAsyncShieldedTRC20
from tronpy.async_tron import AsyncTron as TronModuleAsyncTron
from tronpy.contract import ContractFunctions, ContractMethod
from tronpy.providers import AsyncHTTPProvider as ProvidersAsyncHTTPProvider
from tronpy.providers import HTTPProvider
from tronpy.providers.async_http import AsyncHTTPProvider as AsyncHTTPModuleProvider
from tronpy.tron import Transaction, TransactionBuilder, TransactionRet, Trx


def test_async_names_are_aliases_of_the_new_names():
    pairs = [
        (AsyncTron, Tron),
        (TronModuleAsyncTron, Tron),
        (AsyncTransaction, Transaction),
        (AsyncTransactionBuilder, TransactionBuilder),
        (AsyncTransactionRet, TransactionRet),
        (AsyncTrx, Trx),
        (AsyncContract, Contract),
        (TronModuleAsyncContract, Contract),
        (ContractModuleAsyncContract, Contract),
        (AsyncContractFunctions, ContractFunctions),
        (AsyncContractMethod, ContractMethod),
        (TronModuleAsyncContractMethod, ContractMethod),
        (AsyncShieldedTRC20, ShieldedTRC20),
        (TronModuleAsyncShieldedTRC20, ShieldedTRC20),
        (AsyncHTTPProvider, HTTPProvider),
        (ProvidersAsyncHTTPProvider, HTTPProvider),
        (AsyncHTTPModuleProvider, HTTPProvider),
    ]
    assert all(alias is name for alias, name in pairs)
