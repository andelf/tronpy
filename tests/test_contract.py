import pytest

from tests.utils import check_transaction_structure
from tronpy import AsyncContract, AsyncTron, Contract, Tron
from tronpy.keys import PrivateKey

# test_net address
FROM_ADDR = "TBDCyrZ1hT1PDDFf2yRABwPrFica5qqPUX"
# test_net private key
FROM_PRIV_KEY = PrivateKey(
    bytes.fromhex("fd605fb953fcdabb952be161265a75b8a3ce1c0def2c7db72265f9db9a471be4")
)
# test_net address
TO_ADDR = "TFVfhkyJAULWQbHMgVfgbkmgeGBkHo5zru"
CNR_ADDR = "THi2qJf6XmvTJSpZHc17HgQsmJop6kb3ia"

BYTECODE = (
    "608060405234801561001057600080fd5b5060c78061001f6000396000f3f"
    "e6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11"
    "460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080f"
    "d5b8101908080359060200190929190505050607e565b005b60686088565b604051808281526"
    "0200191505060405180910390f35b8060008190555050565b6000805490509056fea26469706"
    "67358221220c8daade51f673e96205b4a991ab6b94af82edea0f4b57be087ab123f03fc40f264736f6c63430006000033"
)

TRC20_EXPECTED_RESP = {
    "parameter": {
        "value": {
            "owner_address": "410d9dee927cc1ea6b6e67f4993fac317826ea0c26",
            "contract_address": "4154e24764f19b0450d49d4b66270da289666cf82a",
            "data": "a9059cbb0000000000000000000000003c9b65b212316904572826240224750eccce"
            "29a200000000000000000000000000000000000000000000000000000000000003e8",
            "call_token_value": 0,
            "call_value": 0,
            "token_id": 0,
        },
        "type_url": "type.googleapis.com/protocol.TriggerSmartContract",
    },
    "type": "TriggerSmartContract",
}

CREATE_CONTRACT_EXPECTED_RESP = {
    "parameter": {
        "value": {
            "owner_address": "410d9dee927cc1ea6b6e67f4993fac317826ea0c26",
            "new_contract": {
                "origin_address": "410d9dee927cc1ea6b6e67f4993fac317826ea0c26",
                "abi": {
                    "entrys": [
                        {
                            "inputs": [],
                            "name": "get",
                            "outputs": [
                                {"internalType": "uint256", "name": "retVal", "type": "uint256"}
                            ],
                            "stateMutability": "view",
                            "type": "function",
                        }
                    ]
                },
                "bytecode": BYTECODE,
                "call_value": 0,
                "name": "SimpleStore",
                "consume_user_resource_percent": 100,
                "origin_energy_limit": 1,
            },
        },
        "type_url": "type.googleapis.com/protocol.CreateSmartContract",
    },
    "type": "CreateSmartContract",
}


def test_const_functions():
    client = Tron(network="nile")
    contract = client.get_contract(CNR_ADDR)
    assert contract
    assert "name" in dir(contract.functions)
    assert contract.functions.name() == "Example Fixed Supply Token"
    assert contract.functions.decimals() == 2
    assert contract.functions.totalSupply() > 0


@pytest.mark.asyncio
async def test_async_const_functions():
    async with AsyncTron(network="nile") as client:
        contract = await client.get_contract(CNR_ADDR)
        assert contract
        assert "name" in dir(contract.functions)
        assert await contract.functions.name() == "Example Fixed Supply Token"
        assert await contract.functions.decimals() == 2
        assert await contract.functions.totalSupply() > 0


def test_trc20_transfer():
    client = Tron(network="nile")
    contract = client.get_contract(CNR_ADDR)
    tx = (
        contract.functions.transfer(TO_ADDR, 1_000)
        .with_owner(FROM_ADDR)
        .fee_limit(5_000_000)
        .build()
        .sign(FROM_PRIV_KEY)
    )
    check_transaction_structure(tx.to_json(), TRC20_EXPECTED_RESP, 5_000_000, expect_memo=False)


@pytest.mark.asyncio
async def test_async_trc20_transfer():
    async with AsyncTron(network="nile") as client:
        contract = await client.get_contract(CNR_ADDR)
        tx = (
            await (await contract.functions.transfer(TO_ADDR, 1_000))
            .with_owner(FROM_ADDR)
            .fee_limit(5_000_000)
            .build()
        ).sign(FROM_PRIV_KEY)
        check_transaction_structure(tx.to_json(), TRC20_EXPECTED_RESP, 5_000_000, expect_memo=False)


def test_contract_create():
    # TGQgfK497YXmjdgvun9Bg5Zu3xE15v17cu
    client = Tron(network="nile")
    abi = [
        {
            "inputs": [],
            "name": "get",
            "outputs": [{"internalType": "uint256", "name": "retVal", "type": "uint256"}],
            "stateMutability": "view",
            "type": "function",
        }
    ]
    cntr = Contract(name="SimpleStore", bytecode=BYTECODE, abi=abi)
    tx = (
        client.trx.deploy_contract(FROM_ADDR, cntr).fee_limit(5_000_000).build().sign(FROM_PRIV_KEY)
    )
    check_transaction_structure(
        tx.to_json(), CREATE_CONTRACT_EXPECTED_RESP, 5_000_000, expect_memo=False
    )


@pytest.mark.asyncio
async def test_async_contract_create():
    async with AsyncTron(network="nile") as client:
        abi = [
            {
                "inputs": [],
                "name": "get",
                "outputs": [{"internalType": "uint256", "name": "retVal", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function",
            }
        ]
        cntr = AsyncContract(name="SimpleStore", bytecode=BYTECODE, abi=abi)
        tx = (await client.trx.deploy_contract(FROM_ADDR, cntr).fee_limit(5_000_000).build()).sign(
            FROM_PRIV_KEY
        )
        check_transaction_structure(
            tx.to_json(), CREATE_CONTRACT_EXPECTED_RESP, 5_000_000, expect_memo=False
        )
