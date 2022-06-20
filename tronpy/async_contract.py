from typing import Union, Tuple

import tronpy
from tronpy import keys
from tronpy.exceptions import DoubleSpending
from tronpy.contract import Contract, ContractMethod, ContractFunctions, ShieldedTRC20


class AsyncContract(Contract):
    """A smart contract object."""
    @property
    def functions(self) -> "ContractFunctions":
        """The :class:`~ContractFunctions` object, wraps all contract methods."""
        if self._functions is None:
            if self.abi:
                self._functions = AsyncContractFunctions(self)
                return self._functions
            raise ValueError("can not call a contract without ABI")
        return self._functions

    def as_shielded_trc20(self) -> "AsyncShieldedTRC20":
        return AsyncShieldedTRC20(self)


class AsyncContractFunctions(ContractFunctions):
    def __getitem__(self, method: str):
        for method_abi in self._contract.abi:
            if method_abi["type"].lower() == "function" and method_abi["name"] == method:
                return AsyncContractMethod(method_abi, self._contract)

        raise KeyError("contract has no method named '{}'".format(method))


# noinspection PyProtectedMember
class AsyncContractMethod(ContractMethod):
    async def call(self, *args, **kwargs) -> "tronpy.async_tron.AsyncTransactionBuilder":
        """Call the contract method."""
        return await self.__call__(*args, **kwargs)

    async def __call__(self, *args, **kwargs) -> "tronpy.async_tron.AsyncTransactionBuilder":
        """Call the contract method."""
        parameter = self._prepare_parameter(*args, **kwargs)
        return await self._async_trigger_contract(parameter)

    async def _async_trigger_contract(self, parameter):
        if self._abi.get("stateMutability", None).lower() in ["view", "pure"]:
            # const call, contract ret
            ret = await self._client.trigger_const_smart_contract_function(
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
                method=self,
            )


# noinspection PyProtectedMember
class AsyncShieldedTRC20(ShieldedTRC20):
    """Async Shielded TRC20 Wrapper."""
    @property
    async def trc20(self) -> AsyncContract:
        """The corresponding TRC20 contract."""
        if self._trc20 is None:
            trc20_address = "41" + self.shielded._bytecode[-52:-32].hex()
            self._trc20 = self._client.get_contract(trc20_address)
        return await self._trc20

    @property
    async def scale_factor(self) -> int:
        """Scaling factor of the shielded contract."""
        if self._scale_factor is None:
            self._scale_factor = self.shielded.functions.scalingFactor()
        return await self._scale_factor

    async def get_rcm(self) -> str:
        return (await self._client.provider.make_request("wallet/getrcm"))["value"]

    async def mint(
        self, taddr: str, zaddr: str, amount: int, memo: str = ""
    ) -> "tronpy.async_tron.AsyncTransactionBuilder":
        """Mint, transfer from T-address to z-address."""
        rcm = await self.get_rcm()
        payload = {
            "from_amount": str(amount),
            "shielded_receives": {
                "note": {
                    "value": amount // self.scale_factor,
                    "payment_address": zaddr,
                    "rcm": rcm,
                    "memo": memo.encode().hex(),
                }
            },
            "shielded_TRC20_contract_address": keys.to_hex_address(self.shielded.contract_address),
        }

        ret = await self._client.provider.make_request("wallet/createshieldedcontractparameters", payload)
        self._client._handle_api_error(ret)
        parameter = ret["trigger_contract_input"]
        function_signature = self.shielded.functions.mint.function_signature_hash
        return self._client.trx._build_transaction(
            "TriggerSmartContract",
            {
                "owner_address": keys.to_hex_address(taddr),
                "contract_address": keys.to_hex_address(self.shielded.contract_address),
                "data": function_signature + parameter,
            },
            method=self.shielded.functions.mint,
        )

    async def transfer(
        self, zkey: dict, notes: Union[list, dict], *to: Union[Tuple[str, int], Tuple[str, int, str]],
    ) -> "tronpy.async_tron.AsyncTransactionBuilder":
        """Transfer from z-address to z-address."""
        if isinstance(notes, (dict,)):
            notes = [notes]

        assert 1 <= len(notes) <= 2

        spends = []
        spend_amount = 0
        for note in notes:
            if note.get("is_spent", False):
                raise DoubleSpending
            alpha = await self.get_rcm()
            root, path = self.get_path(note.get("position", 0))
            spends.append(
                {"note": note["note"], "alpha": alpha, "root": root, "path": path, "pos": note.get("position", 0)}
            )
            spend_amount += note["note"]["value"]

        receives = []
        receive_amount = 0
        for recv in to:
            addr = recv[0]
            amount = recv[1]
            receive_amount += amount
            if len(recv) == 3:
                memo = recv[2]
            else:
                memo = ""

            rcm = await self.get_rcm()

            receives.append(
                {"note": {"value": amount, "payment_address": addr, "rcm": rcm, "memo": memo.encode().hex()}}
            )

        if spend_amount != receive_amount:
            raise ValueError("spend amount is not equal to receive amount")

        payload = {
            "ask": zkey["ask"],
            "nsk": zkey["nsk"],
            "ovk": zkey["ovk"],
            "shielded_spends": spends,
            "shielded_receives": receives,
            "shielded_TRC20_contract_address": keys.to_hex_address(self.shielded.contract_address),
        }
        ret = await self._client.provider.make_request("wallet/createshieldedcontractparameters", payload)
        self._client._handle_api_error(ret)
        parameter = ret["trigger_contract_input"]
        function_signature = self.shielded.functions.transfer.function_signature_hash
        return self._client.trx._build_transaction(
            "TriggerSmartContract",
            {
                "owner_address": "0000000000000000000000000000000000000000",
                "contract_address": keys.to_hex_address(self.shielded.contract_address),
                "data": function_signature + parameter,
            },
            method=self.shielded.functions.transfer,
        )

    async def burn(
        self, zkey: dict, note: dict, *to: Union[Tuple[str, int], Tuple[str, int, str]]
    ) -> "tronpy.async_tron.AsyncTransactionBuilder":
        """Burn, transfer from z-address to T-address."""
        spends = []
        alpha = await self.get_rcm()
        root, path = self.get_path(note.get("position", 0))
        if note.get("is_spent", False):
            raise DoubleSpending
        spends.append(
            {"note": note["note"], "alpha": alpha, "root": root, "path": path, "pos": note.get("position", 0)}
        )
        change_amount = 0
        receives = []
        to_addr = None
        to_amount = 0
        to_memo = ''
        if not to:
            raise ValueError('burn must have a output')
        for receive in to:
            addr = receive[0]
            amount = receive[1]
            if len(receive) == 3:
                memo = receive[2]
            else:
                memo = ""

            if addr.startswith('ztron1'):
                change_amount += amount
                rcm = await self.get_rcm()
                receives = [
                    {"note": {"value": amount, "payment_address": addr, "rcm": rcm, "memo": memo.encode().hex()}}
                ]
            else:
                # assume T-address
                to_addr = addr
                to_amount = amount
                to_memo = memo

        if note["note"]["value"] * self.scale_factor - change_amount * self.scale_factor != to_amount:
            raise ValueError("Balance amount is wrong")

        payload = {
            "ask": zkey["ask"],
            "nsk": zkey["nsk"],
            "ovk": zkey["ovk"],
            "shielded_spends": spends,
            "shielded_receives": receives,
            "to_amount": str(to_amount),
            "transparent_to_address": keys.to_hex_address(to_addr),
            "shielded_TRC20_contract_address": keys.to_hex_address(self.shielded.contract_address),
        }

        ret = await self._client.provider.make_request("wallet/createshieldedcontractparameters", payload)
        self._client._handle_api_error(ret)
        parameter = ret["trigger_contract_input"]
        function_signature = self.shielded.functions.burn.function_signature_hash
        txn = self._client.trx._build_transaction(
            "TriggerSmartContract",
            {
                "owner_address": "410000000000000000000000000000000000000000",
                "contract_address": keys.to_hex_address(self.shielded.contract_address),
                "data": function_signature + parameter,
            },
            method=self.shielded.functions.burn,
        )
        if to_memo:
            txn = txn.memo(to_memo)
        return txn

    # use zkey pair from wallet/getnewshieldedaddress
    async def scan_incoming_notes(self, zkey: dict, start_block_number: int, end_block_number: int = None) -> list:
        """Scan incoming notes using ivk, ak, nk."""
        if end_block_number is None:
            end_block_number = start_block_number + 1000
        payload = {
            "start_block_index": start_block_number,
            "end_block_index": end_block_number,
            "shielded_TRC20_contract_address": keys.to_hex_address(self.shielded.contract_address),
            "ivk": zkey["ivk"],
            "ak": zkey["ak"],
            "nk": zkey["nk"],
        }
        ret = await self._client.provider.make_request("wallet/scanshieldedtrc20notesbyivk", payload)
        self._client._handle_api_error(ret)
        return self._fix_notes(ret.get("noteTxs", []))

    async def scan_outgoing_notes(
        self, zkey_or_ovk: Union[dict, str], start_block_number: int, end_block_number: int = None
    ) -> list:
        """Scan outgoing notes using ovk."""
        if end_block_number is None:
            end_block_number = start_block_number + 1000

        ovk = zkey_or_ovk
        if isinstance(zkey_or_ovk, (dict,)):
            ovk = zkey_or_ovk["ovk"]

        payload = {
            "start_block_index": start_block_number,
            "end_block_index": end_block_number,
            "shielded_TRC20_contract_address": keys.to_hex_address(self.shielded.contract_address),
            "ovk": ovk,
        }
        ret = await self._client.provider.make_request("wallet/scanshieldedtrc20notesbyovk", payload)
        self._client._handle_api_error(ret)
        return ret.get("noteTxs", [])

    async def is_note_spent(self, zkey: dict, note: dict) -> bool:
        """Is a note spent."""
        payload = dict(note)
        payload["shielded_TRC20_contract_address"] = keys.to_hex_address(self.shielded.contract_address)
        if "position" not in note:
            payload["position"] = 0
        payload["ak"] = zkey["ak"]
        payload["nk"] = zkey["nk"]

        ret = await self._client.provider.make_request("wallet/isshieldedtrc20contractnotespent", payload)

        return ret.get('is_spent', None)
