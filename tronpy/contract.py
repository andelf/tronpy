from typing import Union, Optional


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
        creator_address: str = None,
        owner_address: str = None,
    ):
        self.contract_address = addr
        self.bytecode = assure_bytes(bytecode)
        self.name = name
        self.abi = abi or []

        self.user_resource_percent = user_resource_percent
        self.origin_energy_limit = origin_energy_limit

        self.creator_address = creator_address
        self.owner_address = owner_address

        self._functions = None

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
                print("method_abi", method_abi)
                return ContractMethod(method_abi, self._contract)

        raise KeyError("contract has no method named '{}'".format(method))

    def __getattr__(self, method: str):
        try:
            return self[method]
        except KeyError:
            raise AttributeError("contract has no method named '{}'".format(method))


class ContractMethod(object):
    def __init__(self, abi: dict, contract: Contract):

        self._abi = abi
        self._contract = contract

        self.inputs = abi.get('inputs', [])
        self.outputs = abi.get('outputs', [])

        super().__init__()

    def __call__(self, *args, **kwrags):
        print('calling function', self._abi)
        pass
