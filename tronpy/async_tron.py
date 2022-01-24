import time
import json
import asyncio
from pprint import pprint
from decimal import Decimal
from typing import Union, Tuple, Optional

from tronpy import keys
from tronpy.async_contract import AsyncContract, ShieldedTRC20, AsyncContractMethod
from tronpy.keys import PrivateKey
from tronpy.abi import tron_abi
from tronpy.defaults import conf_for_name
from tronpy.providers.async_http import AsyncHTTPProvider
from tronpy.exceptions import (
    BadSignature,
    BadKey,
    BadHash,
    BlockNotFound,
    AssetNotFound,
    TaposError,
    UnknownError,
    TransactionError,
    ValidationError,
    ApiError,
    AddressNotFound,
    TransactionNotFound,
    TvmError,
    BugInJavaTron,
)

TAddress = str

DEFAULT_CONF = {
    'fee_limit': 10_000_000,
    'timeout': 10.0,  # in second
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

        if receipt.get('result', None) == 'FAILED':
            msg = receipt.get('resMessage', receipt['result'])

            if receipt['receipt']['result'] == 'REVERT':
                try:
                    result = receipt.get('contractResult', [])
                    if result and len(result[0]) > (4 + 32) * 2:
                        error_msg = tron_abi.decode_single('string', bytes.fromhex(result[0])[4 + 32 :])
                        msg = "{}: {}".format(msg, error_msg)
                except Exception:
                    pass
            raise TvmError(msg)

        return self._method.parse_output(receipt['contractResult'][0])


# noinspection PyBroadException,PyProtectedMember
class AsyncTransaction(object):
    """The Transaction object, signed or unsigned."""

    def __init__(self,
                 raw_data: dict,
                 client: "AsyncTron" = None,
                 method: AsyncContractMethod = None,
                 txid: str = "",
                 permission: dict = None,
                 signature: list = None):
        self._raw_data: dict = raw_data
        self._signature: list = signature or []
        self._client = client

        self._method = method

        self.txid: str = txid
        """The transaction id in hex."""

        self._permission: Optional[dict] = permission

        # IMPORTANT must use "Transaction.create" to create a new Transaction

    @classmethod
    async def create(cls, *args, **kwargs) -> Optional["AsyncTransaction"]:
        _tx = cls(*args, **kwargs)
        if not _tx.txid or not _tx._permission:
            await _tx.check_sign_weight()
        return _tx

    async def check_sign_weight(self):
        sign_weight = await self._client.get_sign_weight(self)
        if "transaction" not in sign_weight:
            self._client._handle_api_error(sign_weight)
            raise TransactionError('transaction not in sign_weight')
        self.txid = sign_weight["transaction"]["transaction"]["txID"]
        # when account not exist on-chain
        self._permission = sign_weight.get("permission", None)

    def to_json(self) -> dict:
        return {
            "txID": self.txid, "raw_data": self._raw_data,
            "signature": self._signature, "permission": self._permission
        }

    @classmethod
    async def from_json(cls, data: Union[str, dict], client: "AsyncTron" = None) -> "AsyncTransaction":
        if isinstance(json, str):
            data = json.loads(data)
        return await cls.create(
            client=client,
            txid=data['txID'], permission=data['permission'],
            raw_data=data['raw_data'], signature=data['signature']
        )

    def inspect(self) -> "AsyncTransaction":
        pprint(self.to_json())
        return self

    def sign(self, priv_key: PrivateKey) -> "AsyncTransaction":
        """Sign the transaction with a private key."""

        assert self.txid, "txID not calculated"
        assert self.is_expired is False, 'expired'

        if self._permission is not None:
            addr_of_key = priv_key.public_key.to_hex_address()
            for key in self._permission["keys"]:
                if key["address"] == addr_of_key:
                    break
            else:
                raise BadKey(
                    "provided private key is not in the permission list",
                    "provided {}".format(priv_key.public_key.to_base58check_address()),
                    "required {}".format(self._permission),
                )
        sig = priv_key.sign_msg_hash(bytes.fromhex(self.txid))
        self._signature.append(sig.hex())
        return self

    async def broadcast(self) -> AsyncTransactionRet:
        """Broadcast the transaction to TRON network."""
        return AsyncTransactionRet(await self._client.broadcast(self), client=self._client, method=self._method)

    @property
    def is_expired(self) -> bool:
        return current_timestamp() >= self._raw_data['expiration']

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
class AsyncTransactionBuilder(object):
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

        if inner.get('type', None) in ['TriggerSmartContract', 'CreateSmartContract']:
            self._raw_data["fee_limit"] = self._client.conf['fee_limit']

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

    def fee_limit(self, value: int) -> "AsyncTransactionBuilder":
        """Set fee_limit of the transaction, in `SUN`."""
        self._raw_data["fee_limit"] = value
        return self

    async def build(self, options=None, **kwargs) -> AsyncTransaction:
        """Build the transaction."""
        ref_block_id = await self._client.get_latest_solid_block_id()
        # last 2 byte of block number part
        self._raw_data["ref_block_bytes"] = ref_block_id[12:16]
        # last half part of block hash
        self._raw_data["ref_block_hash"] = ref_block_id[16:32]

        if self._method:
            return await AsyncTransaction.create(self._raw_data, client=self._client, method=self._method)

        return await AsyncTransaction.create(self._raw_data, client=self._client)


# noinspection PyBroadException
class AsyncTrx(object):
    """The Trx(transaction) API."""

    def __init__(self, tron):
        self._tron = tron

    @property
    def client(self) -> "AsyncTron":
        return self._tron

    def _build_transaction(
        self, type_: str, obj: dict, *, method: AsyncContractMethod = None
    ) -> AsyncTransactionBuilder:
        inner = {
            "parameter": {"value": obj, "type_url": "type.googleapis.com/protocol.{}".format(type_)},
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

        if 'owner' in perm:
            for key in perm['owner']['keys']:
                key['address'] = keys.to_hex_address(key['address'])
        if 'actives' in perm:
            for act in perm['actives']:
                for key in act['keys']:
                    key['address'] = keys.to_hex_address(key['address'])
        if perm.get('witness', None):
            for key in perm['witness']['keys']:
                key['address'] = keys.to_hex_address(key['address'])

        return self._build_transaction(
            "AccountPermissionUpdateContract", dict(owner_address=keys.to_hex_address(owner), **perm),
        )

    def account_update(self, owner: TAddress, name: str) -> "AsyncTransactionBuilder":
        """Update account name. An account can only set name once."""
        return self._build_transaction(
            "UpdateAccountContract", {"owner_address": keys.to_hex_address(owner), "account_name": name.encode().hex()},
        )

    def freeze_balance(
        self, owner: TAddress, amount: int, resource: str = "ENERGY", *, receiver: TAddress = None
    ) -> "AsyncTransactionBuilder":
        """Freeze balance to get energy or bandwidth, for 3 days.

        :param resource: Resource type, can be ``"ENERGY"`` or ``"BANDWIDTH"``
        """
        payload = {
            "owner_address": keys.to_hex_address(owner),
            "frozen_balance": amount,
            "frozen_duration": 3,
            "resource": resource,
        }
        if receiver is not None:
            payload["receiver_address"] = keys.to_hex_address(receiver)
        return self._build_transaction("FreezeBalanceContract", payload)

    def unfreeze_balance(
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

    # Witness

    def create_witness(self, owner: TAddress, url: str) -> "AsyncTransactionBuilder":
        """Create a new witness, will consume 1_000 TRX."""
        payload = {"owner_address": keys.to_hex_address(owner), "url": url.encode().hex()}
        return self._build_transaction("WitnessCreateContract", payload)

    def vote_witness(self, owner: TAddress, *votes: Tuple[TAddress, int]) -> "AsyncTransactionBuilder":
        """Vote for witnesses. Empty ``votes`` to clean voted."""
        votes = [dict(vote_address=keys.to_hex_address(addr), vote_count=count) for addr, count in votes]
        payload = {"owner_address": keys.to_hex_address(owner), "votes": votes}
        return self._build_transaction("VoteWitnessContract", payload)

    # Contract

    def deploy_contract(self, owner: TAddress, contract: AsyncContract) -> "AsyncTransactionBuilder":
        """Deploy a new contract on chain."""
        contract._client = self.client
        contract.owner_address = owner
        contract.origin_address = owner
        contract.contract_address = None

        return contract.deploy()


# noinspection PyBroadException
class AsyncTron(object):
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
            self.provider = AsyncHTTPProvider(conf_for_name(network), self.conf['timeout'])
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
        if payload.get("result", None) is True:
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
            elif payload["code"] == "TAPOS_ERROR":
                raise TaposError(msg)
            elif payload["code"] in ["TRANSACTION_EXPIRATION_ERROR", "TOO_BIG_TRANSACTION_ERROR"]:
                raise TransactionError(msg)
            elif payload["code"] == "CONTRACT_VALIDATE_ERROR":
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

        return dict(
            sk=sk, ask=ask, nsk=nsk, ovk=ovk, ak=ak, nk=nk, ivk=ivk, d=d, pkD=pkD, payment_address=payment_address,
        )

    # Account query
    async def get_account(self, addr: TAddress) -> dict:
        """Get account info from an address."""

        ret = await self.provider.make_request(
            "wallet/getaccount", {"address": keys.to_base58check_address(addr), "visible": True}
        )
        if ret:
            return ret
        else:
            raise AddressNotFound("account not found on-chain")

    async def get_account_resource(self, addr: TAddress) -> dict:
        """Get resource info of an account."""

        ret = await self.provider.make_request(
            "wallet/getaccountresource", {"address": keys.to_base58check_address(addr), "visible": True},
        )
        if ret:
            return ret
        else:
            raise AddressNotFound("account not found on-chain")

    async def get_account_balance(self, addr: TAddress) -> Decimal:
        """Get TRX balance of an account. Result in `TRX`."""

        info = await self.get_account(addr)
        return Decimal(info.get("balance", 0)) / 1_000_000

    async def get_account_asset_balances(self, addr: TAddress) -> dict:
        """Get all TRC10 token balances of an account."""
        info = await self.get_account(addr)
        return {p['key']: p['value'] for p in info.get("assetV2", {}) if p['value'] > 0}

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

    # Block query

    async def get_latest_solid_block(self) -> dict:
        return await self.provider.make_request("walletsolidity/getnowblock")

    async def get_latest_solid_block_id(self) -> str:
        """Get latest solid block id in hex."""

        info = await self.provider.make_request("wallet/getnodeinfo")
        return info["solidityBlock"].split(",ID:", 1)[-1]

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
            raise TypeError("can not infer type of {}".format(id_or_num))

        if 'Error' in (block or {}):
            raise BugInJavaTron(block)
        elif block:
            return block
        else:
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

        ret = await self.provider.make_request(
            "walletsolidity/gettransactioninfobyid", {"value": txn_id, "visible": True}
        )
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

    async def get_asset(self, id: int = None, issuer: TAddress = None) -> dict:
        """Get TRC10(asset) info by asset's id or issuer."""
        if id and issuer:
            raise ValueError("either query by id or issuer")
        if id:
            return await self.provider.make_request("wallet/getassetissuebyid", {"value": id, "visible": True})
        else:
            return await self.provider.make_request(
                "wallet/getassetissuebyaccount", {"address": keys.to_base58check_address(issuer), "visible": True},
            )

    async def get_asset_from_name(self, name: str) -> dict:
        """Get asset info from its abbr name, might fail if there're duplicates."""
        assets = [asset for asset in await self.list_assets() if asset['abbr'] == name]
        if assets:
            if len(assets) == 1:
                return assets[0]
            raise ValueError("duplicated assets with the same name", [asset['id'] for asset in assets])
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
            asset["description"] = bytes.fromhex(asset["description"]).decode("utf8", "replace")
            asset["url"] = bytes.fromhex(asset["url"]).decode()
        return assets

    # Smart contract

    async def get_contract(self, addr: TAddress) -> AsyncContract:
        """Get a contract object."""
        addr = keys.to_base58check_address(addr)
        info = await self.provider.make_request("wallet/getcontract", {"value": addr, "visible": True})

        try:
            self._handle_api_error(info)
        except ApiError:
            # your java's null pointer exception sucks
            raise AddressNotFound("contract address not found")

        cntr = AsyncContract(
            addr=addr,
            bytecode=info.get("bytecode", ''),
            name=info.get("name", ""),
            abi=info.get("abi", {}).get("entrys", []),
            origin_energy_limit=info.get("origin_energy_limit", 0),
            user_resource_percent=info.get("consume_user_resource_percent", 100),
            client=self,
        )
        return cntr

    async def get_contract_as_shielded_trc20(self, addr: TAddress) -> ShieldedTRC20:
        """Get a Shielded TRC20 Contract object."""
        contract = await self.get_contract(addr)
        return ShieldedTRC20(contract)

    async def trigger_const_smart_contract_function(
        self, owner_address: TAddress, contract_address: TAddress, function_selector: str, parameter: str,
    ) -> str:
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
        if 'message' in ret.get('result', {}):
            msg = ret['result']['message']
            result = ret.get('constant_result', [])
            try:
                if result and len(result[0]) > (4 + 32) * 2:
                    error_msg = tron_abi.decode_single('string', bytes.fromhex(result[0])[4 + 32 :])
                    msg = "{}: {}".format(msg, error_msg)
            except Exception:
                pass
            raise TvmError(msg)
        return ret["constant_result"][0]

    # Transaction handling

    async def broadcast(self, txn: AsyncTransaction) -> dict:
        payload = await self.provider.make_request("wallet/broadcasttransaction", txn.to_json())
        self._handle_api_error(payload)
        return payload

    async def get_sign_weight(self, txn: AsyncTransaction) -> dict:
        return await self.provider.make_request("wallet/getsignweight", txn.to_json())

    async def close(self):
        if not self.provider.client.is_closed:
            await self.provider.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.provider.client.aclose()
