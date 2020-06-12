from tronpy import patch_abi

from typing import Union, Optional, Any
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
    raise ValueError("bad bytes format")


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
        owner_address: str = "410000000000000000000000000000000000000000",
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
        return "<Contract {}>".format(self.contract_address)

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
            if method_abi["type"] == "Function" and method_abi["name"] == method:
                return ContractMethod(method_abi, self._contract)

        raise KeyError("contract has no method named '{}'".format(method))

    def __getattr__(self, method: str):
        try:
            return self[method]
        except KeyError:
            raise AttributeError("contract has no method named '{}'".format(method))

    def __dir__(self):
        return [method["name"] for method in self._contract.abi if method["type"] == "Function"]

    def __iter__(self):
        yield from [self[method] for method in dir(self)]


class ContractMethod(object):
    def __init__(self, abi: dict, contract: Contract):

        self._abi = abi
        self._contract = contract
        self._owner_address = contract.owner_address
        self._client = contract._client

        self.inputs = abi.get("inputs", [])
        self.outputs = abi.get("outputs", [])

        self.call_value = 0
        self.call_token_value = 0
        self.call_token_id = 0

        super().__init__()

    def __str__(self):
        return self.function_type

    def with_owner(self, addr: str):
        self._owner_address = addr
        return self

    def with_transfer(self, amount: int):
        self.call_value = amount
        return self

    def with_asset_transfer(self, amount: int, token_id: int):
        self.call_token_value = amount
        self.call_token_id = token_id
        return self

    def call(self, *args, **kwargs):
        return self.__call__(*args, **kwargs)

    def parse_output(self, raw: str) -> Any:
        parsed_result = decode_single(self.output_type, bytes.fromhex(raw))
        if len(self.outputs) == 1:
            return parsed_result[0]
        return parsed_result

    def __call__(self, *args, **kwargs):
        parameter = ""

        if args and kwargs:
            raise ValueError("do not mix positional arguments and keyword arguments")

        if len(self.inputs) == 0:
            if args or kwargs:
                raise TypeError("{} expected {} arguments".format(self.name, len(self.inputs)))
        elif args:
            if len(args) != len(self.inputs):
                raise TypeError("wrong number of arguments, require {} got {}".format(len(self.inputs), len(args)))
            parameter = encode_single(self.input_type, args).hex()
        elif kwargs:
            if len(kwargs) != len(self.inputs):
                raise TypeError("wrong number of arguments, require {} got {}".format(len(self.inputs), len(args)))
            args = []
            for arg in self.inputs:
                try:
                    args.append(kwargs[arg['name']])
                except KeyError:
                    raise TypeError("missing argument '{}'".format(arg['name']))
            parameter = encode_single(self.input_type, args).hex()
        else:
            raise TypeError("wrong number of arguments, require {}".format(len(self.inputs)))

        if self._abi.get("stateMutability", None).lower() in ['view', 'pure']:
            # const call, contract ret
            ret = self._client.trigger_const_smart_contract_function(
                self._owner_address, self._contract.contract_address, self.function_signature, parameter,
            )

            return self.parse_output(ret)

        else:
            return self._client.trx._build_transaction(
                "TriggerSmartContract",
                {
                    "owner_address": keys.to_hex_address(self._owner_address),
                    "contract_address": keys.to_hex_address(self._contract.contract_address),
                    "data": self.function_signature_hash + parameter,
                    "call_token_value": self.call_token_value,
                    "call_value": self.call_value,
                    "token_id": self.call_token_id,
                },
            )

    @property
    def name(self):
        return self._abi["name"]

    @property
    def input_type(self):
        return "(" + (",".join(arg["type"] for arg in self.inputs)) + ")"

    @property
    def output_type(self):
        return "(" + (",".join(arg["type"] for arg in self.outputs)) + ")"

    @property
    def function_signature(self):
        return self.name + self.input_type

    @property
    def function_signature_hash(self) -> str:
        return keccak256(self.function_signature.encode())[:4].hex()

    @property
    def function_type(self):
        types = ', '.join(arg["type"] + ' ' + arg.get("name", '') for arg in self.inputs)
        ret = 'function {}({})'.format(self.name, types)
        if self.outputs:
            ret += ' returns ({})'.format(', '.join(arg["type"] + ' ' + arg.get("name", '') for arg in self.outputs))
        return ret
