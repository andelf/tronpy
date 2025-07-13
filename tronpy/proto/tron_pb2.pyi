from typing import ClassVar as _ClassVar
from typing import Iterable as _Iterable
from typing import Mapping as _Mapping
from typing import Optional as _Optional
from typing import Union as _Union

from google.protobuf import any_pb2 as _any_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper

AssetIssue: AccountType
Contract: AccountType
DESCRIPTOR: _descriptor.FileDescriptor
Normal: AccountType

class AccountCreateContract(_message.Message):
    __slots__ = ["account_address", "owner_address", "type"]
    ACCOUNT_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    OWNER_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    account_address: bytes
    owner_address: bytes
    type: AccountType
    def __init__(
        self,
        owner_address: _Optional[bytes] = ...,
        account_address: _Optional[bytes] = ...,
        type: _Optional[_Union[AccountType, str]] = ...,
    ) -> None: ...

class AccountId(_message.Message):
    __slots__ = ["address", "name"]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    address: bytes
    name: bytes
    def __init__(self, name: _Optional[bytes] = ..., address: _Optional[bytes] = ...) -> None: ...

class Transaction(_message.Message):
    __slots__ = ["raw_data", "signature"]

    class Contract(_message.Message):
        __slots__ = ["ContractName", "Permission_id", "parameter", "provider", "type"]

        class ContractType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = []

        AccountCreateContract: Transaction.Contract.ContractType
        AccountPermissionUpdateContract: Transaction.Contract.ContractType
        AccountUpdateContract: Transaction.Contract.ContractType
        AssetIssueContract: Transaction.Contract.ContractType
        CONTRACTNAME_FIELD_NUMBER: _ClassVar[int]
        ClearABIContract: Transaction.Contract.ContractType
        ContractName: bytes
        CreateSmartContract: Transaction.Contract.ContractType
        CustomContract: Transaction.Contract.ContractType
        DelegateResourceContract: Transaction.Contract.ContractType
        ExchangeCreateContract: Transaction.Contract.ContractType
        ExchangeInjectContract: Transaction.Contract.ContractType
        ExchangeTransactionContract: Transaction.Contract.ContractType
        ExchangeWithdrawContract: Transaction.Contract.ContractType
        FreezeBalanceContract: Transaction.Contract.ContractType
        FreezeBalanceV2Contract: Transaction.Contract.ContractType
        GetContract: Transaction.Contract.ContractType
        MarketCancelOrderContract: Transaction.Contract.ContractType
        MarketSellAssetContract: Transaction.Contract.ContractType
        PARAMETER_FIELD_NUMBER: _ClassVar[int]
        PERMISSION_ID_FIELD_NUMBER: _ClassVar[int]
        PROVIDER_FIELD_NUMBER: _ClassVar[int]
        ParticipateAssetIssueContract: Transaction.Contract.ContractType
        Permission_id: int
        ProposalApproveContract: Transaction.Contract.ContractType
        ProposalCreateContract: Transaction.Contract.ContractType
        ProposalDeleteContract: Transaction.Contract.ContractType
        SetAccountIdContract: Transaction.Contract.ContractType
        ShieldedTransferContract: Transaction.Contract.ContractType
        TYPE_FIELD_NUMBER: _ClassVar[int]
        TransferAssetContract: Transaction.Contract.ContractType
        TransferContract: Transaction.Contract.ContractType
        TriggerSmartContract: Transaction.Contract.ContractType
        UnDelegateResourceContract: Transaction.Contract.ContractType
        UnfreezeAssetContract: Transaction.Contract.ContractType
        UnfreezeBalanceContract: Transaction.Contract.ContractType
        UnfreezeBalanceV2Contract: Transaction.Contract.ContractType
        UpdateAssetContract: Transaction.Contract.ContractType
        UpdateBrokerageContract: Transaction.Contract.ContractType
        UpdateEnergyLimitContract: Transaction.Contract.ContractType
        UpdateSettingContract: Transaction.Contract.ContractType
        VoteAssetContract: Transaction.Contract.ContractType
        VoteWitnessContract: Transaction.Contract.ContractType
        WithdrawBalanceContract: Transaction.Contract.ContractType
        WithdrawExpireUnfreezeContract: Transaction.Contract.ContractType
        WitnessCreateContract: Transaction.Contract.ContractType
        WitnessUpdateContract: Transaction.Contract.ContractType
        parameter: _any_pb2.Any
        provider: bytes
        type: Transaction.Contract.ContractType
        def __init__(
            self,
            type: _Optional[_Union[Transaction.Contract.ContractType, str]] = ...,
            parameter: _Optional[_Union[_any_pb2.Any, _Mapping]] = ...,
            provider: _Optional[bytes] = ...,
            ContractName: _Optional[bytes] = ...,
            Permission_id: _Optional[int] = ...,
        ) -> None: ...

    class raw(_message.Message):
        __slots__ = [
            "auths",
            "contract",
            "data",
            "expiration",
            "fee_limit",
            "ref_block_bytes",
            "ref_block_hash",
            "ref_block_num",
            "scripts",
            "timestamp",
        ]
        AUTHS_FIELD_NUMBER: _ClassVar[int]
        CONTRACT_FIELD_NUMBER: _ClassVar[int]
        DATA_FIELD_NUMBER: _ClassVar[int]
        EXPIRATION_FIELD_NUMBER: _ClassVar[int]
        FEE_LIMIT_FIELD_NUMBER: _ClassVar[int]
        REF_BLOCK_BYTES_FIELD_NUMBER: _ClassVar[int]
        REF_BLOCK_HASH_FIELD_NUMBER: _ClassVar[int]
        REF_BLOCK_NUM_FIELD_NUMBER: _ClassVar[int]
        SCRIPTS_FIELD_NUMBER: _ClassVar[int]
        TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        auths: _containers.RepeatedCompositeFieldContainer[authority]
        contract: _containers.RepeatedCompositeFieldContainer[Transaction.Contract]
        data: bytes
        expiration: int
        fee_limit: int
        ref_block_bytes: bytes
        ref_block_hash: bytes
        ref_block_num: int
        scripts: bytes
        timestamp: int
        def __init__(
            self,
            ref_block_bytes: _Optional[bytes] = ...,
            ref_block_num: _Optional[int] = ...,
            ref_block_hash: _Optional[bytes] = ...,
            expiration: _Optional[int] = ...,
            auths: _Optional[_Iterable[_Union[authority, _Mapping]]] = ...,
            data: _Optional[bytes] = ...,
            contract: _Optional[_Iterable[_Union[Transaction.Contract, _Mapping]]] = ...,
            scripts: _Optional[bytes] = ...,
            timestamp: _Optional[int] = ...,
            fee_limit: _Optional[int] = ...,
        ) -> None: ...

    RAW_DATA_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    raw_data: Transaction.raw
    signature: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(
        self, raw_data: _Optional[_Union[Transaction.raw, _Mapping]] = ..., signature: _Optional[_Iterable[bytes]] = ...
    ) -> None: ...

class TransferAssetContract(_message.Message):
    __slots__ = ["amount", "asset_name", "owner_address", "to_address"]
    AMOUNT_FIELD_NUMBER: _ClassVar[int]
    ASSET_NAME_FIELD_NUMBER: _ClassVar[int]
    OWNER_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    TO_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    amount: int
    asset_name: bytes
    owner_address: bytes
    to_address: bytes
    def __init__(
        self,
        asset_name: _Optional[bytes] = ...,
        owner_address: _Optional[bytes] = ...,
        to_address: _Optional[bytes] = ...,
        amount: _Optional[int] = ...,
    ) -> None: ...

class TransferContract(_message.Message):
    __slots__ = ["amount", "owner_address", "to_address"]
    AMOUNT_FIELD_NUMBER: _ClassVar[int]
    OWNER_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    TO_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    amount: int
    owner_address: bytes
    to_address: bytes
    def __init__(
        self, owner_address: _Optional[bytes] = ..., to_address: _Optional[bytes] = ..., amount: _Optional[int] = ...
    ) -> None: ...

class TriggerSmartContract(_message.Message):
    __slots__ = ["call_token_value", "call_value", "contract_address", "data", "owner_address", "token_id"]
    CALL_TOKEN_VALUE_FIELD_NUMBER: _ClassVar[int]
    CALL_VALUE_FIELD_NUMBER: _ClassVar[int]
    CONTRACT_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    OWNER_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    TOKEN_ID_FIELD_NUMBER: _ClassVar[int]
    call_token_value: int
    call_value: int
    contract_address: bytes
    data: bytes
    owner_address: bytes
    token_id: int
    def __init__(
        self,
        owner_address: _Optional[bytes] = ...,
        contract_address: _Optional[bytes] = ...,
        call_value: _Optional[int] = ...,
        data: _Optional[bytes] = ...,
        call_token_value: _Optional[int] = ...,
        token_id: _Optional[int] = ...,
    ) -> None: ...

class authority(_message.Message):
    __slots__ = ["account", "permission_name"]
    ACCOUNT_FIELD_NUMBER: _ClassVar[int]
    PERMISSION_NAME_FIELD_NUMBER: _ClassVar[int]
    account: AccountId
    permission_name: bytes
    def __init__(
        self, account: _Optional[_Union[AccountId, _Mapping]] = ..., permission_name: _Optional[bytes] = ...
    ) -> None: ...

class AccountType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
