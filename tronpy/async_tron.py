import asyncio
import contextlib
import json
import time
from decimal import Decimal
from pprint import pprint
from typing import Optional, Union

from tronpy import keys
from tronpy.abi import tron_abi
from tronpy.async_contract import AsyncContract, AsyncContractMethod, ShieldedTRC20
from tronpy.defaults import PROTOBUF_NOT_INSTALLED_ERROR_MESSAGE, conf_for_name
from tronpy.exceptions import (
    AddressNotFound,
    ApiError,
    AssetNotFound,
    BadHash,
    BadKey,
    BadSignature,
    BlockNotFound,
    BugInJavaTron,
    ProtobufImportError,
    TaposError,
    TransactionError,
    TransactionNotFound,
    TvmError,
    UnknownError,
    ValidationError,
)
from tronpy.hdwallet import TRON_DEFAULT_PATH, generate_mnemonic, key_from_seed, seed_from_mnemonic
from tronpy.keys import PrivateKey
from tronpy.providers.async_http import AsyncHTTPProvider

try:
    from tronpy import proto
except ProtobufImportError:
    proto = None

TAddress = str

DEFAULT_CONF = {
    "fee_limit": 10_000_000,
    "timeout": 10.0,  # in second
}


def current_timestamp() -> int:
    return int(time.time() * 1000)


# noinspection PyBroadException
class AsyncTransactionRet(dict):
    def __init__(self, iterable, client: "AsyncTron", method: AsyncContractMethod = None):
        super().__init__(iterable)

        self._client = client
        self._txid = self["txid"]
        self._method = method

    @property
    def txid(self):
        """The transaction id in hex."""
        return self._txid

    async def wait(self, timeout=30, interval=1.6, solid=False) -> dict:
        """Wait the transaction to be on chain.

        :returns: TransactionInfo
        """

        get_transaction_info = self._client.get_transaction_info
        if solid:
            get_transaction_info = self._client.get_solid_transaction_info

        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                return await get_transaction_info(self._txid)
            except TransactionNotFound:
                await asyncio.sleep(interval)

        raise TransactionNotFound("timeout and can not find the transaction")

    async def result(self, timeout=30, interval=1.6, solid=False) -> dict:
        """Wait the contract calling result.

        :returns: Result of contract method
        """
        if self._method is None:
            raise TypeError("Not a smart contract call")

        receipt = await self.wait(timeout, interval, solid)

        if receipt.get("result", None) == "FAILED":
            msg = receipt.get("resMessage", receipt["result"])

            if receipt["receipt"]["result"] == "REVERT":
                with contextlib.suppress(Exception):
                    result = receipt.get("contractResult", [])
                    if result and len(result[0]) > (4 + 32) * 2:
                        error_msg = tron_abi.decode_single("string", bytes.fromhex(result[0])[4 + 32 :])
                        msg = f"{msg}: {error_msg}"
            raise TvmError(msg)

        return self._method.parse_output(receipt["contractResult"][0])


EMPTY = object()


# noinspection PyBroadException,PyProtectedMember
class AsyncTransaction:
    """The Transaction object, signed or unsigned."""

    def __init__(
        self,
        raw_data: dict,
        client: "AsyncTron" = None,
        method: AsyncContractMethod = None,
        txid: str = "",
        permission: dict = None,
        signature: list = None,
    ):
        self._raw_data: dict = raw_data.get("raw_data", raw_data)
        self._signature: list = raw_data.get("signature", signature or [])
        self._client = client

        self._method = method

        self.txid: str = raw_data.get("txID", txid)
        """The transaction id in hex."""

        self._permission: Optional[dict] = raw_data.get("permission", permission)

        # IMPORTANT must use "Transaction.create" to create a new Transaction

    @classmethod
    async def create(cls, *args, **kwargs) -> Optional["AsyncTransaction"]:
        _tx = cls(*args, **kwargs)
        if not _tx.txid or _tx._permission is EMPTY:
            await _tx.check_sign_weight()
        return _tx

    async def check_sign_weight(self):
        sign_weight = await self._client.get_sign_weight(self)
        if "transaction" not in sign_weight:
            self._client._handle_api_error(sign_weight)
            raise TransactionError("transaction not in sign_weight")
        self.txid = sign_weight["transaction"]["transaction"]["txID"]
        # when account not exist on-chain
        self._permission = sign_weight.get("permission", None)

    def to_json(self) -> dict:
        return {
            "txID": self.txid,
            "raw_data": self._raw_data,
            "signature": self._signature,
            "permission": self._permission if self._permission is not EMPTY else None,
        }

    @classmethod
    async def from_json(cls, data: Union[str, dict], client: "AsyncTron" = None) -> "AsyncTransaction":
        if isinstance(json, str):
            data = json.loads(data)
        return await cls.create(
            client=client,
            txid=data["txID"],
            permission=data["permission"],
            raw_data=data["raw_data"],
            signature=data["signature"],
        )

    def inspect(self) -> "AsyncTransaction":
        pprint(self.to_json())
        return self

    def sign(self, priv_key: PrivateKey) -> "AsyncTransaction":
        """Sign the transaction with a private key."""

        if not self.txid:
            raise ValueError("txID not calculated")
        if self.is_expired:
            raise ValueError("expired")

        if self._permission is not None:
            addr_of_key = priv_key.public_key.to_hex_address()
            for key in self._permission["keys"]:
                if key["address"] == addr_of_key:
                    break
            else:
                raise BadKey(
                    "provided private key is not in the permission list",
                    f"provided {priv_key.public_key.to_base58check_address()}",
                    f"required {self._permission}",
                )
        sig = priv_key.sign_msg_hash(bytes.fromhex(self.txid))
        self._signature.append(sig.hex())
        return self

    async def broadcast(self) -> AsyncTransactionRet:
        """Broadcast the transaction to TRON network."""
        return AsyncTransactionRet(await self._client.broadcast(self), client=self._client, method=self._method)

    def set_signature(self, signature: list) -> "AsyncTransaction":
        """set async transaction signature"""
        self._signature = signature
        return self

    @property
    def is_expired(self) -> bool:
        return current_timestamp() >= self._raw_data["expiration"]

    async def update(self):
        """update Transaction, change ref_block and txID, remove all signature"""
        self._raw_data["timestamp"] = current_timestamp()
        self._raw_data["expiration"] = self._raw_data["timestamp"] + 60_000
        ref_block_id = await self._client.get_latest_solid_block_id()
        # last 2 byte of block number part
        self._raw_data["ref_block_bytes"] = ref_block_id[12:16]
        # last half part of block hash
        self._raw_data["ref_block_hash"] = ref_block_id[16:32]

        self.txid = ""
        self._permission = None
        self._signature = []
        sign_weight = await self._client.get_sign_weight(self)
        if "transaction" not in sign_weight:
            self._client._handle_api_error(sign_weight)
            return  # unreachable
        self.txid = sign_weight["transaction"]["transaction"]["txID"]

        # when account not exist on-chain
        self._permission = sign_weight.get("permission", None)
        # remove all _signature
        self._signature = []

    def __str__(self):
        return json.dumps(self.to_json(), indent=2)


# noinspection PyBroadException
class AsyncTransactionBuilder:
    """TransactionBuilder, to build a :class:`~Transaction` object."""

    def __init__(self, inner: dict, client: "AsyncTron", method: AsyncContractMethod = None):
        self._client = client
        self._raw_data = {
            "contract": [inner],
            "timestamp": current_timestamp(),
            "expiration": current_timestamp() + 60_000,
            "ref_block_bytes": None,
            "ref_block_hash": None,
        }

        if inner.get("type") in ["TriggerSmartContract", "CreateSmartContract"]:
            self._raw_data["fee_limit"] = self._client.conf["fee_limit"]

        self._method = method

    def with_owner(self, addr: TAddress) -> "AsyncTransactionBuilder":
        """Set owner of the transaction."""
        if "owner_address" in self._raw_data["contract"][0]["parameter"]["value"]:
            self._raw_data["contract"][0]["parameter"]["value"]["owner_address"] = keys.to_hex_address(addr)
        else:
            raise TypeError("can not set owner")
        return self

    def permission_id(self, perm_id: int) -> "AsyncTransactionBuilder":
        """Set permission_id of the transaction."""
        self._raw_data["contract"][0]["Permission_id"] = perm_id
        return self

    def memo(self, memo: Union[str, bytes]) -> "AsyncTransactionBuilder":
        """Set memo of the transaction."""
        data = memo.encode() if isinstance(memo, (str,)) else memo
        self._raw_data["data"] = data.hex()
        return self

    def expiration(self, expiration: int) -> "AsyncTransactionBuilder":
        self._raw_data["expiration"] = current_timestamp() + expiration
        return self

    def fee_limit(self, value: int) -> "AsyncTransactionBuilder":
        """Set fee_limit of the transaction, in `SUN`."""
        self._raw_data["fee_limit"] = value
        return self

    async def build(self, *, offline: bool = False, ref_block_id: str = None, **kwargs) -> AsyncTransaction:
        """Build the transaction."""
        if offline:
            if not ref_block_id:
                raise ValueError("ref_block_id is required when building offline transactions")
            if proto is None:
                raise ImportError(PROTOBUF_NOT_INSTALLED_ERROR_MESSAGE)
        else:
            ref_block_id = await self._client.get_latest_solid_block_id()
        self._raw_data["ref_block_bytes"] = ref_block_id[12:16]
        self._raw_data["ref_block_hash"] = ref_block_id[16:32]
        if offline:
            txid = proto.calculate_txid_from_raw_data(self._raw_data)
            return AsyncTransaction(
                self._raw_data,
                client=None,
                method=self._method,
                txid=txid,
                permission=None,
            )
        return await AsyncTransaction.create(self._raw_data, client=self._client, method=self._method)


# noinspection PyBroadException
class AsyncTrx:
    """The Trx(transaction) API."""

    def __init__(self, tron):
        self._tron = tron

    @property
    def client(self) -> "AsyncTron":
        return self._tron

    def _build_transaction(self, type_: str, obj: dict, *, method: AsyncContractMethod = None) -> AsyncTransactionBuilder:
        inner = {
            "parameter": {"value": obj, "type_url": f"type.googleapis.com/protocol.{type_}"},
            "type": type_,
        }
        if method:
            return AsyncTransactionBuilder(inner, client=self.client, method=method)
        return AsyncTransactionBuilder(inner, client=self.client)

    def transfer(self, from_: TAddress, to: TAddress, amount: int) -> AsyncTransactionBuilder:
        """Transfer TRX. ``amount`` in `SUN`."""
        return self._build_transaction(
            "TransferContract",
            {"owner_address": keys.to_hex_address(from_), "to_address": keys.to_hex_address(to), "amount": amount},
        )

    # TRC10 asset

    def asset_transfer(self, from_: TAddress, to: TAddress, amount: int, token_id: int) -> AsyncTransactionBuilder:
        """Transfer TRC10 tokens."""
        return self._build_transaction(
            "TransferAssetContract",
            {
                "owner_address": keys.to_hex_address(from_),
                "to_address": keys.to_hex_address(to),
                "amount": amount,
                "asset_name": str(token_id).encode().hex(),
            },
        )

    def asset_issue(
        self,
        owner: TAddress,
        abbr: str,
        total_supply: int,
        *,
        url: str,
        name: str = None,
        description: str = "",
        start_time: int = None,
        end_time: int = None,
        precision: int = 6,
        frozen_supply: list = None,
        trx_num: int = 1,
        num: int = 1,
    ) -> AsyncTransactionBuilder:
        """Issue a TRC10 token.

        Almost all parameters have resonable defaults.
        """
        if name is None:
            name = abbr

        if start_time is None:
            # use default expiration
            start_time = current_timestamp() + 60_000

        if end_time is None:
            # use default expiration
            end_time = current_timestamp() + 60_000 + 1

        if frozen_supply is None:
            frozen_supply = []

        return self._build_transaction(
            "AssetIssueContract",
            {
                "owner_address": keys.to_hex_address(owner),
                "abbr": abbr.encode().hex(),
                "name": name.encode().hex(),
                "total_supply": total_supply,
                "precision": precision,
                "url": url.encode().hex(),
                "description": description.encode().hex(),
                "start_time": start_time,
                "end_time": end_time,
                "frozen_supply": frozen_supply,
                "trx_num": trx_num,
                "num": num,
                "public_free_asset_net_limit": 0,
                "free_asset_net_limit": 0,
            },
        )

    # Account

    def account_permission_update(self, owner: TAddress, perm: dict) -> "AsyncTransactionBuilder":
        """Update account permission.

        :param owner: Address of owner
        :param perm: Permission dict from :meth:`~tronpy.Tron.get_account_permission`
        """

        if "owner" in perm:
            for key in perm["owner"]["keys"]:
                key["address"] = keys.to_hex_address(key["address"])
        if "actives" in perm:
            for act in perm["actives"]:
                for key in act["keys"]:
                    key["address"] = keys.to_hex_address(key["address"])
        if perm.get("witness"):
            for key in perm["witness"]["keys"]:
                key["address"] = keys.to_hex_address(key["address"])

        return self._build_transaction(
            "AccountPermissionUpdateContract",
            dict(owner_address=keys.to_hex_address(owner), **perm),
        )

    def account_update(self, owner: TAddress, name: str) -> "AsyncTransactionBuilder":
        """Update account name. An account can only set name once."""
        return self._build_transaction(
            "UpdateAccountContract",
            {"owner_address": keys.to_hex_address(owner), "account_name": name.encode().hex()},
        )

    def freeze_balance(self, owner: TAddress, amount: int, resource: str = "ENERGY") -> "AsyncTransactionBuilder":
        """Freeze balance to get energy or bandwidth, for 3 days.

        :param resource: Resource type, can be ``"ENERGY"`` or ``"BANDWIDTH"``
        """
        payload = {
            "owner_address": keys.to_hex_address(owner),
            "frozen_balance": amount,
            "resource": resource,
        }
        return self._build_transaction("FreezeBalanceV2Contract", payload)

    def withdraw_stake_balance(self, owner: TAddress) -> "AsyncTransactionBuilder":
        """Withdraw all stake v2 balance after waiting for 14 days since unfreeze_balance call.

        :param owner:
        """
        payload = {
            "owner_address": keys.to_hex_address(owner),
        }
        return self._build_transaction("WithdrawExpireUnfreezeContract", payload)

    def unfreeze_balance(
        self, owner: TAddress, resource: str = "ENERGY", *, unfreeze_balance: int
    ) -> "AsyncTransactionBuilder":
        """Unfreeze balance to get TRX back.

        :param resource: Resource type, can be ``"ENERGY"`` or ``"BANDWIDTH"``
        """
        payload = {
            "owner_address": keys.to_hex_address(owner),
            "unfreeze_balance": unfreeze_balance,
            "resource": resource,
        }
        return self._build_transaction("UnfreezeBalanceV2Contract", payload)

    def unfreeze_balance_legacy(
        self, owner: TAddress, resource: str = "ENERGY", receiver: TAddress = None
    ) -> "AsyncTransactionBuilder":
        """Unfreeze balance to get TRX back.

        :param resource: Resource type, can be ``"ENERGY"`` or ``"BANDWIDTH"``
        """
        payload = {
            "owner_address": keys.to_hex_address(owner),
            "resource": resource,
        }
        if receiver is not None:
            payload["receiver_address"] = keys.to_hex_address(receiver)
        return self._build_transaction("UnfreezeBalanceContract", payload)

    def delegate_resource(
        self,
        owner: TAddress,
        receiver: TAddress,
        balance: int,
        resource: str = "BANDWIDTH",
        lock: bool = False,
        lock_period: int = None,
    ) -> "AsyncTransactionBuilder":
        """Delegate bandwidth or energy resources to other accounts in Stake2.0.

        :param owner:
        :param receiver:
        :param balance:
        :param resource: Resource type, can be ``"ENERGY"`` or ``"BANDWIDTH"``
        :param lock: Optionally lock delegated resources for 3 days.
        :param lock_period: Optionally lock delegated resources for a specific period. Default: 3 days.
        """

        payload = {
            "owner_address": keys.to_hex_address(owner),
            "receiver_address": keys.to_hex_address(receiver),
            "balance": balance,
            "resource": resource,
            "lock": lock,
        }
        if lock_period is not None:
            payload["lock_period"] = lock_period

        return self._build_transaction("DelegateResourceContract", payload)

    def undelegate_resource(
        self, owner: TAddress, receiver: TAddress, balance: int, resource: str = "BANDWIDTH"
    ) -> "AsyncTransactionBuilder":
        """Cancel the delegation of bandwidth or energy resources to other accounts in Stake2.0

        :param owner:
        :param receiver:
        :param balance:
        :param resource: Resource type, can be ``"ENERGY"`` or ``"BANDWIDTH"``
        """

        payload = {
            "owner_address": keys.to_hex_address(owner),
            "receiver_address": keys.to_hex_address(receiver),
            "balance": balance,
            "resource": resource,
        }

        return self._build_transaction("UnDelegateResourceContract", payload)

    # Witness

    def create_witness(self, owner: TAddress, url: str) -> "AsyncTransactionBuilder":
        """Create a new witness, will consume 1_000 TRX."""
        payload = {"owner_address": keys.to_hex_address(owner), "url": url.encode().hex()}
        return self._build_transaction("WitnessCreateContract", payload)

    def vote_witness(self, owner: TAddress, *votes: tuple[TAddress, int]) -> "AsyncTransactionBuilder":
        """Vote for witnesses. Empty ``votes`` to clean voted."""
        votes = [{"vote_address": keys.to_hex_address(addr), "vote_count": count} for addr, count in votes]
        payload = {"owner_address": keys.to_hex_address(owner), "votes": votes}
        return self._build_transaction("VoteWitnessContract", payload)

    def withdraw_rewards(self, owner: TAddress) -> "AsyncTransactionBuilder":
        """Withdraw voting rewards."""
        payload = {"owner_address": keys.to_hex_address(owner)}
        return self._build_transaction("WithdrawBalanceContract", payload)

    # Contract

    def deploy_contract(self, owner: TAddress, contract: AsyncContract) -> "AsyncTransactionBuilder":
        """Deploy a new contract on chain."""
        contract._client = self.client
        contract.owner_address = owner
        contract.origin_address = owner
        contract.contract_address = None

        return contract.deploy()


# noinspection PyBroadException
class AsyncTron:
    """The Async TRON API Client.

    :param provider: An :class:`~tronpy.providers.HTTPProvider` object, can be configured to use private node
    :param network: Which network to connect, one of ``"mainnet"``, ``"shasta"``, ``"nile"``, or ``"tronex"``
    """

    # Address API
    is_address = staticmethod(keys.is_address)
    """Is object a TRON address, both hex format and base58check format."""

    is_base58check_address = staticmethod(keys.is_base58check_address)
    """Is object an address in base58check format."""

    is_hex_address = staticmethod(keys.is_hex_address)
    """Is object an address in hex str format."""

    to_base58check_address = staticmethod(keys.to_base58check_address)
    """Convert address of any format to a base58check format."""

    to_hex_address = staticmethod(keys.to_hex_address)
    """Convert address of any format to a hex format."""

    to_canonical_address = staticmethod(keys.to_base58check_address)

    def __init__(self, provider: AsyncHTTPProvider = None, *, network: str = "mainnet", conf: dict = None):
        self.conf = DEFAULT_CONF
        """The config dict."""

        if conf is not None:
            self.conf = dict(DEFAULT_CONF, **conf)

        if provider is None:
            self.provider = AsyncHTTPProvider(conf_for_name(network), self.conf["timeout"])
        elif isinstance(provider, (AsyncHTTPProvider,)):
            self.provider = provider
        else:
            raise TypeError("provider is not a HTTPProvider")

        self._trx = AsyncTrx(self)

    @property
    def trx(self) -> AsyncTrx:
        """
        Helper object to send various transactions.

        :type: Trx
        """
        return self._trx

    def _handle_api_error(self, payload: dict):
        if payload.get("result") is True:
            return
        if "Error" in payload:
            # class java.lang.NullPointerException : null
            raise ApiError(payload["Error"])
        if "code" in payload:
            try:
                msg = bytes.fromhex(payload["message"]).decode()
            except Exception:
                msg = payload.get("message", str(payload))

            if payload["code"] == "SIGERROR":
                raise BadSignature(msg)
            if payload["code"] == "TAPOS_ERROR":
                raise TaposError(msg)
            if payload["code"] in ["TRANSACTION_EXPIRATION_ERROR", "TOO_BIG_TRANSACTION_ERROR"]:
                raise TransactionError(msg)
            if payload["code"] == "CONTRACT_VALIDATE_ERROR":
                raise ValidationError(msg)
            raise UnknownError(msg, payload["code"])
        if "result" in payload and isinstance(payload["result"], (dict,)):
            return self._handle_api_error(payload["result"])

    # Address utilities

    def generate_address(self, priv_key=None) -> dict:
        """Generate a random address."""
        if priv_key is None:
            priv_key = PrivateKey.random()
        return {
            "base58check_address": priv_key.public_key.to_base58check_address(),
            "hex_address": priv_key.public_key.to_hex_address(),
            "private_key": priv_key.hex(),
            "public_key": priv_key.public_key.hex(),
        }

    def generate_address_from_mnemonic(self, mnemonic: str, passphrase: str = "", account_path: str = TRON_DEFAULT_PATH):
        """
        Generate address from a mnemonic.

        :param str mnemonic: space-separated list of BIP39 mnemonic seed words
        :param str passphrase: Optional passphrase used to encrypt the mnemonic
        :param str account_path: Specify an alternate HD path for deriving the seed using
            BIP32 HD wallet key derivation.
        """
        seed = seed_from_mnemonic(mnemonic, passphrase)
        key = key_from_seed(seed, account_path)
        priv_key = PrivateKey(key)
        return {
            "base58check_address": priv_key.public_key.to_base58check_address(),
            "hex_address": priv_key.public_key.to_hex_address(),
            "private_key": priv_key.hex(),
            "public_key": priv_key.public_key.hex(),
        }

    def generate_address_with_mnemonic(
        self, passphrase: str = "", num_words: int = 12, language: str = "english", account_path: str = TRON_DEFAULT_PATH
    ):
        r"""
        Create a new address and related mnemonic.

        Creates a new address, and returns it alongside the mnemonic that can be used to regenerate it using any BIP39-compatible wallet.

        :param str passphrase: Extra passphrase to encrypt the seed phrase
        :param int num_words: Number of words to use with seed phrase. Default is 12 words.
                              Must be one of [12, 15, 18, 21, 24].
        :param str language: Language to use for BIP39 mnemonic seed phrase.
        :param str account_path: Specify an alternate HD path for deriving the seed using
            BIP32 HD wallet key derivation.
        """  # noqa: E501
        mnemonic = generate_mnemonic(num_words, language)
        return self.generate_address_from_mnemonic(mnemonic, passphrase, account_path), mnemonic

    def get_address_from_passphrase(self, passphrase: str) -> dict:
        """Get an address from a passphrase, compatiable with `wallet/createaddress`."""
        priv_key = PrivateKey.from_passphrase(passphrase.encode())
        return self.generate_address(priv_key)

    async def generate_zkey(self) -> dict:
        """Generate a random shielded address."""
        return await self.provider.make_request("wallet/getnewshieldedaddress")

    async def get_zkey_from_sk(self, sk: str, d: str = None) -> dict:
        """Get the shielded address from sk(spending key) and d(diversifier)."""
        if len(sk) != 64:
            raise BadKey("32 byte sk required")
        if d and len(d) != 22:
            raise BadKey("11 byte d required")

        esk = await self.provider.make_request("wallet/getexpandedspendingkey", {"value": sk})
        ask = esk["ask"]
        nsk = esk["nsk"]
        ovk = esk["ovk"]
        ak = (await self.provider.make_request("wallet/getakfromask", {"value": ask}))["value"]
        nk = (await self.provider.make_request("wallet/getnkfromnsk", {"value": nsk}))["value"]

        ivk = (await self.provider.make_request("wallet/getincomingviewingkey", {"ak": ak, "nk": nk}))["ivk"]

        if d is None:
            d = (await self.provider.make_request("wallet/getdiversifier"))["d"]

        ret = await self.provider.make_request("wallet/getzenpaymentaddress", {"ivk": ivk, "d": d})
        pkD = ret["pkD"]
        payment_address = ret["payment_address"]

        return {
            "sk": sk,
            "ask": ask,
            "nsk": nsk,
            "ovk": ovk,
            "ak": ak,
            "nk": nk,
            "ivk": ivk,
            "d": d,
            "pkD": pkD,
            "payment_address": payment_address,
        }

    # Account query
    async def get_account(self, addr: TAddress) -> dict:
        """Get account info from an address."""

        ret = await self.provider.make_request(
            "wallet/getaccount", {"address": keys.to_base58check_address(addr), "visible": True}
        )
        if ret:
            return ret
        raise AddressNotFound("account not found on-chain")

    # Bandwidth query
    async def get_bandwidth(self, addr: TAddress) -> int:
        """Query the bandwidth of the account"""

        ret = await self.provider.make_request(
            "wallet/getaccountnet", {"address": keys.to_base58check_address(addr), "visible": True}
        )
        if ret:
            # (freeNetLimit - freeNetUsed) + (NetLimit - NetUsed)
            return ret["freeNetLimit"] - ret.get("freeNetUsed", 0) + ret.get("NetLimit", 0) - ret.get("NetUsed", 0)
        raise AddressNotFound("account not found on-chain")

    async def get_energy(self, address: str) -> int:
        """Query the energy of the account"""
        account_info = await self.get_account_resource(address)
        energy_limit = account_info.get("EnergyLimit", 0)
        energy_used = account_info.get("EnergyUsed", 0)
        return energy_limit - energy_used

    async def get_account_resource(self, addr: TAddress) -> dict:
        """Get resource info of an account."""

        ret = await self.provider.make_request(
            "wallet/getaccountresource",
            {"address": keys.to_base58check_address(addr), "visible": True},
        )
        if ret:
            return ret
        raise AddressNotFound("account not found on-chain")

    async def get_account_balance(self, addr: TAddress) -> Decimal:
        """Get TRX balance of an account. Result in `TRX`."""

        info = await self.get_account(addr)
        return Decimal(info.get("balance", 0)) / 1_000_000

    async def get_account_asset_balances(self, addr: TAddress) -> dict:
        """Get all TRC10 token balances of an account."""
        info = await self.get_account(addr)
        return {p["key"]: p["value"] for p in info.get("assetV2", {}) if p["value"] > 0}

    async def get_account_asset_balance(self, addr: TAddress, token_id: Union[int, str]) -> int:
        """Get TRC10 token balance of an account. Result is in raw amount."""
        if int(token_id) < 1000000 or int(token_id) > 1999999:
            raise ValueError("invalid token_id range")

        balances = await self.get_account_asset_balances(addr)
        return balances.get(str(token_id), 0)

    async def get_account_permission(self, addr: TAddress) -> dict:
        """Get account's permission info from an address. Can be used in `account_permission_update`."""

        addr = keys.to_base58check_address(addr)
        # will check account existence
        info = await self.get_account(addr)
        # For old accounts prior to AccountPermissionUpdate, these fields are not set.
        # So default permission is for backward compatibility.
        default_witness = None
        if info.get("is_witness", None):
            default_witness = {
                "type": "Witness",
                "id": 1,
                "permission_name": "witness",
                "threshold": 1,
                "keys": [{"address": addr, "weight": 1}],
            }
        return {
            "owner": info.get(
                "owner_permission",
                {"permission_name": "owner", "threshold": 1, "keys": [{"address": addr, "weight": 1}]},
            ),
            "actives": info.get(
                "active_permission",
                [
                    {
                        "type": "Active",
                        "id": 2,
                        "permission_name": "active",
                        "threshold": 1,
                        "operations": "7fff1fc0033e0100000000000000000000000000000000000000000000000000",
                        "keys": [{"address": addr, "weight": 1}],
                    }
                ],
            ),
            "witness": info.get("witness_permission", default_witness),
        }

    async def get_delegated_resource_v2(self, fromAddr: TAddress, toAddr: TAddress) -> dict:
        """Query the amount of delegatable resources share of the specified resource type for an address"""
        return await self.provider.make_request(
            "wallet/getdelegatedresourcev2",
            {
                "fromAddress": keys.to_base58check_address(fromAddr),
                "toAddress": keys.to_base58check_address(toAddr),
                "visible": True,
            },
        )

    async def get_can_delegated_max_size(self, address: TAddress, resource: str = "ENERGY") -> dict:
        """Query the amount of delegatable resources share of the specified resource type for an address

        Args:
            address (TAddress):
            resource (str, optional): Resource type, can be ``"ENERGY"`` or ``"BANDWIDTH"``. Defaults to "ENERGY".

        Returns:
            dict: Response data
        """
        return await self.provider.make_request(
            "wallet/getcandelegatedmaxsize",
            {"owner_address": keys.to_base58check_address(address), "type": 1 if resource == "ENERGY" else 0, "visible": True},
        )

    async def get_delegated_resource_account_index_v2(self, addr: TAddress) -> dict:
        """Query the resource delegation index by an account"""
        return await self.provider.make_request(
            "wallet/getdelegatedresourceaccountindexv2",
            {
                "value": keys.to_base58check_address(addr),
                "visible": True,
            },
        )

    # Block query

    async def get_latest_solid_block(self) -> dict:
        return await self.provider.make_request("walletsolidity/getnowblock")

    async def get_latest_solid_block_id(self) -> str:
        """Get latest solid block id in hex."""

        try:
            info = await self.provider.make_request("wallet/getnodeinfo")
            return info["solidityBlock"].split(",ID:", 1)[-1]
        except Exception:
            info = await self.get_latest_solid_block()
            return info["blockID"]

    async def get_latest_solid_block_number(self) -> int:
        """Get latest solid block number. Implemented via `wallet/getnodeinfo`,
        which is faster than `walletsolidity/getnowblock`."""
        info = await self.provider.make_request("wallet/getnodeinfo")
        return int(info["solidityBlock"].split(",ID:", 1)[0].replace("Num:", "", 1))

    async def get_latest_block(self) -> dict:
        """Get latest block."""
        return await self.provider.make_request("wallet/getnowblock", {"visible": True})

    async def get_latest_block_id(self) -> str:
        """Get latest block id in hex."""

        info = await self.provider.make_request("wallet/getnodeinfo")
        return info["block"].split(",ID:", 1)[-1]

    async def get_latest_block_number(self) -> int:
        """Get latest block number. Implemented via `wallet/getnodeinfo`, which is faster than `wallet/getnowblock`."""

        info = await self.provider.make_request("wallet/getnodeinfo")
        return int(info["block"].split(",ID:", 1)[0].replace("Num:", "", 1))

    async def get_block(self, id_or_num: Union[None, str, int] = None, *, visible: bool = True) -> dict:
        """Get block from a block id or block number.

        :param id_or_num: Block number, or Block hash(id), or ``None`` (default) to get the latest block.
        :param visible: Use ``visible=False`` to get non-base58check addresses and strings instead of hex strings.
        """

        if isinstance(id_or_num, (int,)):
            block = await self.provider.make_request("wallet/getblockbynum", {"num": id_or_num, "visible": visible})
        elif isinstance(id_or_num, (str,)):
            block = await self.provider.make_request("wallet/getblockbyid", {"value": id_or_num, "visible": visible})
        elif id_or_num is None:
            block = await self.provider.make_request("wallet/getnowblock", {"visible": visible})
        else:
            raise TypeError(f"can not infer type of {id_or_num}")

        if "Error" in (block or {}):
            raise BugInJavaTron(block)
        if block:
            return block
        raise BlockNotFound

    async def get_transaction(self, txn_id: str) -> dict:
        """Get transaction from a transaction id."""

        if len(txn_id) != 64:
            raise BadHash("wrong transaction hash length")

        ret = await self.provider.make_request("wallet/gettransactionbyid", {"value": txn_id, "visible": True})
        self._handle_api_error(ret)
        if ret:
            return ret
        raise TransactionNotFound

    async def get_solid_transaction(self, txn_id: str) -> dict:
        """Get transaction from a transaction id, must be in solid block."""

        if len(txn_id) != 64:
            raise BadHash("wrong transaction hash length")

        ret = await self.provider.make_request("walletsolidity/gettransactionbyid", {"value": txn_id, "visible": True})
        self._handle_api_error(ret)
        if ret:
            return ret
        raise TransactionNotFound

    async def get_transaction_info(self, txn_id: str) -> dict:
        """Get transaction receipt info from a transaction id."""

        if len(txn_id) != 64:
            raise BadHash("wrong transaction hash length")

        ret = await self.provider.make_request("wallet/gettransactioninfobyid", {"value": txn_id, "visible": True})
        self._handle_api_error(ret)
        if ret:
            return ret
        raise TransactionNotFound

    async def get_solid_transaction_info(self, txn_id: str) -> dict:
        """Get transaction receipt info from a transaction id, must be in solid block."""

        if len(txn_id) != 64:
            raise BadHash("wrong transaction hash length")

        ret = await self.provider.make_request("walletsolidity/gettransactioninfobyid", {"value": txn_id, "visible": True})
        self._handle_api_error(ret)
        if ret:
            return ret
        raise TransactionNotFound

    # Chain parameters

    async def list_witnesses(self) -> list:
        """List all witnesses, including SR, SRP, and SRC."""
        # NOTE: visible parameter is ignored
        ret = await self.provider.make_request("wallet/listwitnesses", {"visible": True})
        witnesses = ret.get("witnesses", [])
        for witness in witnesses:
            witness["address"] = keys.to_base58check_address(witness["address"])

        return witnesses

    async def list_nodes(self) -> list:
        """List all nodes that current API node is connected to."""
        # NOTE: visible parameter is ignored
        ret = await self.provider.make_request("wallet/listnodes", {"visible": True})
        nodes = ret.get("nodes", [])
        for node in nodes:
            node["address"]["host"] = bytes.fromhex(node["address"]["host"]).decode()
        return nodes

    async def get_node_info(self) -> dict:
        """Get current API node' info."""

        return await self.provider.make_request("wallet/getnodeinfo", {"visible": True})

    async def get_chain_parameters(self) -> dict:
        """List all chain parameters, values that can be changed via proposal."""
        params = await self.provider.make_request("wallet/getchainparameters", {"visible": True})
        return params.get("chainParameter", [])

    # Asset (TRC10)

    async def get_asset(self, asset_id: int = None, issuer: TAddress = None) -> dict:
        """Get TRC10(asset) info by asset's id or issuer."""
        if asset_id and issuer:
            raise ValueError("either query by id or issuer")
        if asset_id:
            return await self.provider.make_request("wallet/getassetissuebyid", {"value": asset_id, "visible": True})
        return await self.provider.make_request(
            "wallet/getassetissuebyaccount",
            {"address": keys.to_base58check_address(issuer), "visible": True},
        )

    async def get_asset_from_name(self, name: str) -> dict:
        """Get asset info from its abbr name, might fail if there're duplicates."""
        assets = [asset for asset in await self.list_assets() if asset["abbr"] == name]
        if assets:
            if len(assets) == 1:
                return assets[0]
            raise ValueError("duplicated assets with the same name", [asset["id"] for asset in assets])
        raise AssetNotFound

    async def list_assets(self) -> list:
        """List all TRC10 tokens(assets)."""
        ret = await self.provider.make_request("wallet/getassetissuelist", {"visible": True})
        assets = ret["assetIssue"]
        for asset in assets:
            asset["id"] = int(asset["id"])
            asset["owner_address"] = keys.to_base58check_address(asset["owner_address"])
            asset["name"] = bytes.fromhex(asset["name"]).decode()
            if "abbr" in asset:
                asset["abbr"] = bytes.fromhex(asset["abbr"]).decode()
            else:
                asset["abbr"] = ""
            if "description" in asset:
                asset["description"] = bytes.fromhex(asset["description"]).decode("utf8", "replace")
            else:
                asset["description"] = ""
            asset["url"] = bytes.fromhex(asset["url"]).decode()
        return assets

    # Smart contract

    async def get_contract(self, addr: TAddress) -> AsyncContract:
        """Get a contract object."""
        addr = keys.to_base58check_address(addr)
        info = await self.provider.make_request("wallet/getcontract", {"value": addr, "visible": True})

        try:
            self._handle_api_error(info)
        except ApiError as e:
            # your java's null pointer exception sucks
            raise AddressNotFound("contract address not found") from e

        return AsyncContract(
            addr=addr,
            bytecode=info.get("bytecode", ""),
            name=info.get("name", ""),
            abi=info.get("abi", {}).get("entrys", []),
            origin_energy_limit=info.get("origin_energy_limit", 0),
            user_resource_percent=info.get("consume_user_resource_percent", 100),
            origin_address=info.get("origin_address", ""),
            code_hash=info.get("code_hash", ""),
            client=self,
        )

    async def get_contract_info(self, addr: TAddress) -> dict:
        """Queries a contract's information from the blockchain"""
        addr = keys.to_base58check_address(addr)
        info = await self.provider.make_request("wallet/getcontractinfo", {"value": addr, "visible": True})

        try:
            self._handle_api_error(info)
        except ApiError as e:
            raise AddressNotFound("contract address not found") from e

        return info

    async def get_contract_as_shielded_trc20(self, addr: TAddress) -> ShieldedTRC20:
        """Get a Shielded TRC20 Contract object."""
        contract = await self.get_contract(addr)
        return ShieldedTRC20(contract)

    async def trigger_constant_contract(
        self,
        owner_address: TAddress,
        contract_address: TAddress,
        function_selector: str,
        parameter: str,
    ) -> dict:
        ret = await self.provider.make_request(
            "wallet/triggerconstantcontract",
            {
                "owner_address": keys.to_base58check_address(owner_address),
                "contract_address": keys.to_base58check_address(contract_address),
                "function_selector": function_selector,
                "parameter": parameter,
                "visible": True,
            },
        )
        self._handle_api_error(ret)
        if "message" in ret.get("result", {}):
            msg = ret["result"]["message"]
            result = ret.get("constant_result", [])
            with contextlib.suppress(Exception):
                if result and len(result[0]) > (4 + 32) * 2:
                    error_msg = tron_abi.decode_single("string", bytes.fromhex(result[0])[4 + 32 :])
                    msg = f"{msg}: {error_msg}"
            raise TvmError(msg)
        return ret

    async def trigger_const_smart_contract_function(
        self,
        owner_address: TAddress,
        contract_address: TAddress,
        function_selector: str,
        parameter: str,
    ) -> str:
        ret = await self.trigger_constant_contract(owner_address, contract_address, function_selector, parameter)
        return ret["constant_result"][0]

    # Transaction handling

    async def broadcast(self, txn: AsyncTransaction) -> dict:
        payload = await self.provider.make_request("wallet/broadcasttransaction", txn.to_json())
        self._handle_api_error(payload)
        return payload

    async def get_sign_weight(self, txn: AsyncTransaction) -> dict:
        return await self.provider.make_request("wallet/getsignweight", txn.to_json())

    async def get_estimated_energy(
        self,
        owner_address: TAddress,
        contract_address: TAddress,
        function_selector: str,
        parameter: str,
    ) -> int:
        """Returns an estimated energy of calling a contract from the chain."""
        params = {
            "owner_address": keys.to_base58check_address(owner_address),
            "contract_address": keys.to_base58check_address(contract_address),
            "function_selector": function_selector,
            "parameter": parameter,
            "visible": True,
        }
        ret = await self.provider.make_request("wallet/estimateenergy", params)
        self._handle_api_error(ret)
        return ret["energy_required"]

    async def close(self):
        if not self.provider.client.is_closed:
            await self.provider.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.provider.client.aclose()
