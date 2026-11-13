"""Old names kept for compatibility. Use the names from `tronpy.contract` instead."""

from tronpy.contract import Contract as AsyncContract
from tronpy.contract import ContractFunctions as AsyncContractFunctions
from tronpy.contract import ContractMethod as AsyncContractMethod
from tronpy.contract import ShieldedTRC20 as AsyncShieldedTRC20

__all__ = ["AsyncContract", "AsyncContractFunctions", "AsyncContractMethod", "AsyncShieldedTRC20"]
