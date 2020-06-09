
from tronpy import patch_abi

from typing import Union, Optional
from eth_abi import encode_single, decode_single
from Crypto.Hash import keccak

from tronpy import keys
import tronpy






def keccak256(data: bytes) -> bytes:
    hasher = keccak.new(digest_bits=256)
    hasher.update(data)
    return hasher.digest()


def assure_bytes(value: Union[str, bytes]) -> bytes:
    if isinstance(value, (str,)):
        return bytes.fromhex(value)
    if isinstance(value, (bytes,)):
        return value
    raise ValueError('bad bytes format')


class Contract(object):
    def __init__(
        self,
        addr=None,
        *,
        bytecode: Union[str, bytes],
        name: str = None,
        abi: Optional[dict] = None,
        user_resource_percent: int = 100,
        origin_energy_limit: int = 0,
        origin_address: str = None,
        owner_address: str = '410000000000000000000000000000000000000000',
        client=None,
    ):
        self.contract_address = addr
        self.bytecode = assure_bytes(bytecode)
        self.name = name
        self.abi = abi or []

        self.user_resource_percent = user_resource_percent
        self.origin_energy_limit = origin_energy_limit

        self.origin_address = origin_address
        self.owner_address = owner_address

        self._functions = None
        self._client = client

        super().__init__()

    def __str__(self):
        return '<Contract {}>'.format(self.contract_address)

    @property
    def functions(self):
        if self._functions is None:
            if self.abi:
                self._functions = ContractFunctions(self)
                return self._functions
            raise ValueError("can not call a contract without ABI")
        return self._functions


class ContractFunctions(object):
    def __init__(self, contract):
        self._contract = contract
        super().__init__()

    def __getitem__(self, method: str):
        for method_abi in self._contract.abi:
            if method_abi['type'] == 'Function' and method_abi['name'] == method:
                return ContractMethod(method_abi, self._contract)

        raise KeyError("contract has no method named '{}'".format(method))

    def __getattr__(self, method: str):
        try:
            return self[method]
        except KeyError:
            raise AttributeError("contract has no method named '{}'".format(method))

    def __dir__(self):
        return super().__dir__() + [method['name'] for method in self._contract.abi if method['type'] == 'Function']


class ContractMethod(object):
    def __init__(self, abi: dict, contract: Contract):

        self._abi = abi
        self._contract = contract
        self._owner_address = contract.owner_address
        self._client = contract._client

        self.inputs = abi.get('inputs', [])
        self.outputs = abi.get('outputs', [])

        super().__init__()

    def __call__(self, *args, **kwrags):
        # print('calling function', self._abi)
        # print(self.function_signature)
        # print(self.function_signature_hash)

        parameter = ''

        if args and kwrags:
            raise ValueError("do not mix positional arguments and keyword arguments")

        if len(self.inputs) == 0:
            if args or kwrags:
                raise TypeError("{} expected {} arguments".format(self.name, len(self.inputs)))
        elif args:
            parameter = encode_single(self.input_type, args).hex()
        elif kwrags:
            pass


        if self._abi.get('constant', None):
            # const call
            ret = self._client.trigger_const_smart_contract_function(
                self._owner_address, self._contract.contract_address, self.function_signature, parameter
            )

            parsed_result = decode_single(self.output_type, bytes.fromhex(ret))
            if len(self.outputs) == 1:
                return parsed_result[0]
            return parsed_result

        """
        return self._client.trx._build_inner_transaction(
            "TriggerConstantContract",
            {
                "owner_address": keys.to_hex_address(self._owner_address),
                "contract_address": keys.to_hex_address(self._client.contract_address),
                "function_selector": self.function_signature,
                "parameter": "",
                "visible": True,
            },
        )
        """

    @property
    def name(self):
        return self._abi['name']

    @property
    def input_type(self):
        return '(' + (','.join(arg['type'] for arg in self.inputs)) + ')'

    @property
    def output_type(self):
        return '(' + (','.join(arg['type'] for arg in self.outputs)) + ')'


    @property
    def function_signature(self):
        return self.name + self.input_type

    @property
    def function_signature_hash(self) -> str:
        return keccak256(self.function_signature.encode())[:4].hex()
