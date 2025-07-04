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

DESCRIPTOR: _descriptor.FileDescriptor

class TransferContract(_message.Message):
    __slots__ = ("owner_address", "to_address", "amount")
    OWNER_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    TO_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    AMOUNT_FIELD_NUMBER: _ClassVar[int]
    owner_address: bytes
    to_address: bytes
    amount: int
    def __init__(
        self, owner_address: _Optional[bytes] = ..., to_address: _Optional[bytes] = ..., amount: _Optional[int] = ...
    ) -> None: ...

class TriggerSmartContract(_message.Message):
    __slots__ = ("owner_address", "contract_address", "call_value", "data", "call_token_value", "token_id")
    OWNER_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    CONTRACT_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    CALL_VALUE_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    CALL_TOKEN_VALUE_FIELD_NUMBER: _ClassVar[int]
    TOKEN_ID_FIELD_NUMBER: _ClassVar[int]
    owner_address: bytes
    contract_address: bytes
    call_value: int
    data: bytes
    call_token_value: int
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

class AccountId(_message.Message):
    __slots__ = ("name", "address")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    name: bytes
    address: bytes
    def __init__(self, name: _Optional[bytes] = ..., address: _Optional[bytes] = ...) -> None: ...

class authority(_message.Message):
    __slots__ = ("account", "permission_name")
    ACCOUNT_FIELD_NUMBER: _ClassVar[int]
    PERMISSION_NAME_FIELD_NUMBER: _ClassVar[int]
    account: AccountId
    permission_name: bytes
    def __init__(
        self, account: _Optional[_Union[AccountId, _Mapping]] = ..., permission_name: _Optional[bytes] = ...
    ) -> None: ...

class MarketOrderDetail(_message.Message):
    __slots__ = ("makerOrderId", "takerOrderId", "fillSellQuantity", "fillBuyQuantity")
    MAKERORDERID_FIELD_NUMBER: _ClassVar[int]
    TAKERORDERID_FIELD_NUMBER: _ClassVar[int]
    FILLSELLQUANTITY_FIELD_NUMBER: _ClassVar[int]
    FILLBUYQUANTITY_FIELD_NUMBER: _ClassVar[int]
    makerOrderId: bytes
    takerOrderId: bytes
    fillSellQuantity: int
    fillBuyQuantity: int
    def __init__(
        self,
        makerOrderId: _Optional[bytes] = ...,
        takerOrderId: _Optional[bytes] = ...,
        fillSellQuantity: _Optional[int] = ...,
        fillBuyQuantity: _Optional[int] = ...,
    ) -> None: ...

class Transaction(_message.Message):
    __slots__ = ("raw_data", "signature", "ret")

    class Contract(_message.Message):
        __slots__ = ("type", "parameter", "provider", "ContractName", "Permission_id")

        class ContractType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            AccountCreateContract: _ClassVar[Transaction.Contract.ContractType]
            TransferContract: _ClassVar[Transaction.Contract.ContractType]
            TransferAssetContract: _ClassVar[Transaction.Contract.ContractType]
            VoteAssetContract: _ClassVar[Transaction.Contract.ContractType]
            VoteWitnessContract: _ClassVar[Transaction.Contract.ContractType]
            WitnessCreateContract: _ClassVar[Transaction.Contract.ContractType]
            AssetIssueContract: _ClassVar[Transaction.Contract.ContractType]
            WitnessUpdateContract: _ClassVar[Transaction.Contract.ContractType]
            ParticipateAssetIssueContract: _ClassVar[Transaction.Contract.ContractType]
            AccountUpdateContract: _ClassVar[Transaction.Contract.ContractType]
            FreezeBalanceContract: _ClassVar[Transaction.Contract.ContractType]
            UnfreezeBalanceContract: _ClassVar[Transaction.Contract.ContractType]
            WithdrawBalanceContract: _ClassVar[Transaction.Contract.ContractType]
            UnfreezeAssetContract: _ClassVar[Transaction.Contract.ContractType]
            UpdateAssetContract: _ClassVar[Transaction.Contract.ContractType]
            ProposalCreateContract: _ClassVar[Transaction.Contract.ContractType]
            ProposalApproveContract: _ClassVar[Transaction.Contract.ContractType]
            ProposalDeleteContract: _ClassVar[Transaction.Contract.ContractType]
            SetAccountIdContract: _ClassVar[Transaction.Contract.ContractType]
            CustomContract: _ClassVar[Transaction.Contract.ContractType]
            CreateSmartContract: _ClassVar[Transaction.Contract.ContractType]
            TriggerSmartContract: _ClassVar[Transaction.Contract.ContractType]
            GetContract: _ClassVar[Transaction.Contract.ContractType]
            UpdateSettingContract: _ClassVar[Transaction.Contract.ContractType]
            ExchangeCreateContract: _ClassVar[Transaction.Contract.ContractType]
            ExchangeInjectContract: _ClassVar[Transaction.Contract.ContractType]
            ExchangeWithdrawContract: _ClassVar[Transaction.Contract.ContractType]
            ExchangeTransactionContract: _ClassVar[Transaction.Contract.ContractType]
            UpdateEnergyLimitContract: _ClassVar[Transaction.Contract.ContractType]
            AccountPermissionUpdateContract: _ClassVar[Transaction.Contract.ContractType]
            ClearABIContract: _ClassVar[Transaction.Contract.ContractType]
            UpdateBrokerageContract: _ClassVar[Transaction.Contract.ContractType]
            ShieldedTransferContract: _ClassVar[Transaction.Contract.ContractType]
            MarketSellAssetContract: _ClassVar[Transaction.Contract.ContractType]
            MarketCancelOrderContract: _ClassVar[Transaction.Contract.ContractType]
            FreezeBalanceV2Contract: _ClassVar[Transaction.Contract.ContractType]
            UnfreezeBalanceV2Contract: _ClassVar[Transaction.Contract.ContractType]
            WithdrawExpireUnfreezeContract: _ClassVar[Transaction.Contract.ContractType]
            DelegateResourceContract: _ClassVar[Transaction.Contract.ContractType]
            UnDelegateResourceContract: _ClassVar[Transaction.Contract.ContractType]
            CancelAllUnfreezeV2Contract: _ClassVar[Transaction.Contract.ContractType]

        AccountCreateContract: Transaction.Contract.ContractType
        TransferContract: Transaction.Contract.ContractType
        TransferAssetContract: Transaction.Contract.ContractType
        VoteAssetContract: Transaction.Contract.ContractType
        VoteWitnessContract: Transaction.Contract.ContractType
        WitnessCreateContract: Transaction.Contract.ContractType
        AssetIssueContract: Transaction.Contract.ContractType
        WitnessUpdateContract: Transaction.Contract.ContractType
        ParticipateAssetIssueContract: Transaction.Contract.ContractType
        AccountUpdateContract: Transaction.Contract.ContractType
        FreezeBalanceContract: Transaction.Contract.ContractType
        UnfreezeBalanceContract: Transaction.Contract.ContractType
        WithdrawBalanceContract: Transaction.Contract.ContractType
        UnfreezeAssetContract: Transaction.Contract.ContractType
        UpdateAssetContract: Transaction.Contract.ContractType
        ProposalCreateContract: Transaction.Contract.ContractType
        ProposalApproveContract: Transaction.Contract.ContractType
        ProposalDeleteContract: Transaction.Contract.ContractType
        SetAccountIdContract: Transaction.Contract.ContractType
        CustomContract: Transaction.Contract.ContractType
        CreateSmartContract: Transaction.Contract.ContractType
        TriggerSmartContract: Transaction.Contract.ContractType
        GetContract: Transaction.Contract.ContractType
        UpdateSettingContract: Transaction.Contract.ContractType
        ExchangeCreateContract: Transaction.Contract.ContractType
        ExchangeInjectContract: Transaction.Contract.ContractType
        ExchangeWithdrawContract: Transaction.Contract.ContractType
        ExchangeTransactionContract: Transaction.Contract.ContractType
        UpdateEnergyLimitContract: Transaction.Contract.ContractType
        AccountPermissionUpdateContract: Transaction.Contract.ContractType
        ClearABIContract: Transaction.Contract.ContractType
        UpdateBrokerageContract: Transaction.Contract.ContractType
        ShieldedTransferContract: Transaction.Contract.ContractType
        MarketSellAssetContract: Transaction.Contract.ContractType
        MarketCancelOrderContract: Transaction.Contract.ContractType
        FreezeBalanceV2Contract: Transaction.Contract.ContractType
        UnfreezeBalanceV2Contract: Transaction.Contract.ContractType
        WithdrawExpireUnfreezeContract: Transaction.Contract.ContractType
        DelegateResourceContract: Transaction.Contract.ContractType
        UnDelegateResourceContract: Transaction.Contract.ContractType
        CancelAllUnfreezeV2Contract: Transaction.Contract.ContractType
        TYPE_FIELD_NUMBER: _ClassVar[int]
        PARAMETER_FIELD_NUMBER: _ClassVar[int]
        PROVIDER_FIELD_NUMBER: _ClassVar[int]
        CONTRACTNAME_FIELD_NUMBER: _ClassVar[int]
        PERMISSION_ID_FIELD_NUMBER: _ClassVar[int]
        type: Transaction.Contract.ContractType
        parameter: _any_pb2.Any
        provider: bytes
        ContractName: bytes
        Permission_id: int
        def __init__(
            self,
            type: _Optional[_Union[Transaction.Contract.ContractType, str]] = ...,
            parameter: _Optional[_Union[_any_pb2.Any, _Mapping]] = ...,
            provider: _Optional[bytes] = ...,
            ContractName: _Optional[bytes] = ...,
            Permission_id: _Optional[int] = ...,
        ) -> None: ...

    class Result(_message.Message):
        __slots__ = (
            "fee",
            "ret",
            "contractRet",
            "assetIssueID",
            "withdraw_amount",
            "unfreeze_amount",
            "exchange_received_amount",
            "exchange_inject_another_amount",
            "exchange_withdraw_another_amount",
            "exchange_id",
            "shielded_transaction_fee",
            "orderId",
            "orderDetails",
            "withdraw_expire_amount",
            "cancel_unfreezeV2_amount",
        )

        class code(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            SUCESS: _ClassVar[Transaction.Result.code]
            FAILED: _ClassVar[Transaction.Result.code]

        SUCESS: Transaction.Result.code
        FAILED: Transaction.Result.code

        class contractResult(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            DEFAULT: _ClassVar[Transaction.Result.contractResult]
            SUCCESS: _ClassVar[Transaction.Result.contractResult]
            REVERT: _ClassVar[Transaction.Result.contractResult]
            BAD_JUMP_DESTINATION: _ClassVar[Transaction.Result.contractResult]
            OUT_OF_MEMORY: _ClassVar[Transaction.Result.contractResult]
            PRECOMPILED_CONTRACT: _ClassVar[Transaction.Result.contractResult]
            STACK_TOO_SMALL: _ClassVar[Transaction.Result.contractResult]
            STACK_TOO_LARGE: _ClassVar[Transaction.Result.contractResult]
            ILLEGAL_OPERATION: _ClassVar[Transaction.Result.contractResult]
            STACK_OVERFLOW: _ClassVar[Transaction.Result.contractResult]
            OUT_OF_ENERGY: _ClassVar[Transaction.Result.contractResult]
            OUT_OF_TIME: _ClassVar[Transaction.Result.contractResult]
            JVM_STACK_OVER_FLOW: _ClassVar[Transaction.Result.contractResult]
            UNKNOWN: _ClassVar[Transaction.Result.contractResult]
            TRANSFER_FAILED: _ClassVar[Transaction.Result.contractResult]
            INVALID_CODE: _ClassVar[Transaction.Result.contractResult]

        DEFAULT: Transaction.Result.contractResult
        SUCCESS: Transaction.Result.contractResult
        REVERT: Transaction.Result.contractResult
        BAD_JUMP_DESTINATION: Transaction.Result.contractResult
        OUT_OF_MEMORY: Transaction.Result.contractResult
        PRECOMPILED_CONTRACT: Transaction.Result.contractResult
        STACK_TOO_SMALL: Transaction.Result.contractResult
        STACK_TOO_LARGE: Transaction.Result.contractResult
        ILLEGAL_OPERATION: Transaction.Result.contractResult
        STACK_OVERFLOW: Transaction.Result.contractResult
        OUT_OF_ENERGY: Transaction.Result.contractResult
        OUT_OF_TIME: Transaction.Result.contractResult
        JVM_STACK_OVER_FLOW: Transaction.Result.contractResult
        UNKNOWN: Transaction.Result.contractResult
        TRANSFER_FAILED: Transaction.Result.contractResult
        INVALID_CODE: Transaction.Result.contractResult

        class CancelUnfreezeV2AmountEntry(_message.Message):
            __slots__ = ("key", "value")
            KEY_FIELD_NUMBER: _ClassVar[int]
            VALUE_FIELD_NUMBER: _ClassVar[int]
            key: str
            value: int
            def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...

        FEE_FIELD_NUMBER: _ClassVar[int]
        RET_FIELD_NUMBER: _ClassVar[int]
        CONTRACTRET_FIELD_NUMBER: _ClassVar[int]
        ASSETISSUEID_FIELD_NUMBER: _ClassVar[int]
        WITHDRAW_AMOUNT_FIELD_NUMBER: _ClassVar[int]
        UNFREEZE_AMOUNT_FIELD_NUMBER: _ClassVar[int]
        EXCHANGE_RECEIVED_AMOUNT_FIELD_NUMBER: _ClassVar[int]
        EXCHANGE_INJECT_ANOTHER_AMOUNT_FIELD_NUMBER: _ClassVar[int]
        EXCHANGE_WITHDRAW_ANOTHER_AMOUNT_FIELD_NUMBER: _ClassVar[int]
        EXCHANGE_ID_FIELD_NUMBER: _ClassVar[int]
        SHIELDED_TRANSACTION_FEE_FIELD_NUMBER: _ClassVar[int]
        ORDERID_FIELD_NUMBER: _ClassVar[int]
        ORDERDETAILS_FIELD_NUMBER: _ClassVar[int]
        WITHDRAW_EXPIRE_AMOUNT_FIELD_NUMBER: _ClassVar[int]
        CANCEL_UNFREEZEV2_AMOUNT_FIELD_NUMBER: _ClassVar[int]
        fee: int
        ret: Transaction.Result.code
        contractRet: Transaction.Result.contractResult
        assetIssueID: str
        withdraw_amount: int
        unfreeze_amount: int
        exchange_received_amount: int
        exchange_inject_another_amount: int
        exchange_withdraw_another_amount: int
        exchange_id: int
        shielded_transaction_fee: int
        orderId: bytes
        orderDetails: _containers.RepeatedCompositeFieldContainer[MarketOrderDetail]
        withdraw_expire_amount: int
        cancel_unfreezeV2_amount: _containers.ScalarMap[str, int]
        def __init__(
            self,
            fee: _Optional[int] = ...,
            ret: _Optional[_Union[Transaction.Result.code, str]] = ...,
            contractRet: _Optional[_Union[Transaction.Result.contractResult, str]] = ...,
            assetIssueID: _Optional[str] = ...,
            withdraw_amount: _Optional[int] = ...,
            unfreeze_amount: _Optional[int] = ...,
            exchange_received_amount: _Optional[int] = ...,
            exchange_inject_another_amount: _Optional[int] = ...,
            exchange_withdraw_another_amount: _Optional[int] = ...,
            exchange_id: _Optional[int] = ...,
            shielded_transaction_fee: _Optional[int] = ...,
            orderId: _Optional[bytes] = ...,
            orderDetails: _Optional[_Iterable[_Union[MarketOrderDetail, _Mapping]]] = ...,
            withdraw_expire_amount: _Optional[int] = ...,
            cancel_unfreezeV2_amount: _Optional[_Mapping[str, int]] = ...,
        ) -> None: ...

    class raw(_message.Message):
        __slots__ = (
            "ref_block_bytes",
            "ref_block_num",
            "ref_block_hash",
            "expiration",
            "auths",
            "data",
            "contract",
            "scripts",
            "timestamp",
            "fee_limit",
        )
        REF_BLOCK_BYTES_FIELD_NUMBER: _ClassVar[int]
        REF_BLOCK_NUM_FIELD_NUMBER: _ClassVar[int]
        REF_BLOCK_HASH_FIELD_NUMBER: _ClassVar[int]
        EXPIRATION_FIELD_NUMBER: _ClassVar[int]
        AUTHS_FIELD_NUMBER: _ClassVar[int]
        DATA_FIELD_NUMBER: _ClassVar[int]
        CONTRACT_FIELD_NUMBER: _ClassVar[int]
        SCRIPTS_FIELD_NUMBER: _ClassVar[int]
        TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        FEE_LIMIT_FIELD_NUMBER: _ClassVar[int]
        ref_block_bytes: bytes
        ref_block_num: int
        ref_block_hash: bytes
        expiration: int
        auths: _containers.RepeatedCompositeFieldContainer[authority]
        data: bytes
        contract: _containers.RepeatedCompositeFieldContainer[Transaction.Contract]
        scripts: bytes
        timestamp: int
        fee_limit: int
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
    RET_FIELD_NUMBER: _ClassVar[int]
    raw_data: Transaction.raw
    signature: _containers.RepeatedScalarFieldContainer[bytes]
    ret: _containers.RepeatedCompositeFieldContainer[Transaction.Result]
    def __init__(
        self,
        raw_data: _Optional[_Union[Transaction.raw, _Mapping]] = ...,
        signature: _Optional[_Iterable[bytes]] = ...,
        ret: _Optional[_Iterable[_Union[Transaction.Result, _Mapping]]] = ...,
    ) -> None: ...
