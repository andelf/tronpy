from tronpy import Tron, Contract
from tronpy.keys import PrivateKey


def test_const_functions():
    client = Tron(network='nile')

    contract = client.get_contract('THi2qJf6XmvTJSpZHc17HgQsmJop6kb3ia')
    assert contract

    assert 'name' in dir(contract.functions)

    print(dir(contract.functions))
    print(repr(contract.functions.name()))
    print(repr(contract.functions.decimals()))

    assert contract.functions.totalSupply() > 0

    for f in contract.functions:
        print(f)


def test_trc20_transfer():
    # TGQgfK497YXmjdgvun9Bg5Zu3xE15v17cu
    priv_key = PrivateKey(bytes.fromhex("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"))

    client = Tron(network='nile')

    contract = client.get_contract('THi2qJf6XmvTJSpZHc17HgQsmJop6kb3ia')
    print('Balance', contract.functions.balanceOf('TGQgfK497YXmjdgvun9Bg5Zu3xE15v17cu'))
    txn = (
        contract.functions.transfer.with_owner('TGQgfK497YXmjdgvun9Bg5Zu3xE15v17cu')
        .call('TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA', 1_000)
        .fee_limit(1_000_000)
        .build()
        .sign(priv_key)
        .inspect()
        .broadcast()
    )

    print(txn)
    receipt = txn.wait()
    print(receipt)
    if 'contractResult' in receipt:
        print('result:', contract.functions.transfer.parse_output(receipt['contractResult'][0]))


def test_contract_create():
    # TGQgfK497YXmjdgvun9Bg5Zu3xE15v17cu
    priv_key = PrivateKey(bytes.fromhex("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"))
    client = Tron(network='nile')

    bytecode = "608060405234801561001057600080fd5b5060c78061001f6000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea2646970667358221220c8daade51f673e96205b4a991ab6b94af82edea0f4b57be087ab123f03fc40f264736f6c63430006000033"
    abi = [
        {
            "inputs": [],
            "name": "get",
            "outputs": [{"internalType": "uint256", "name": "retVal", "type": "uint256"}],
            "stateMutability": "view",
            "type": "function",
        }
    ]

    cntr = Contract(name="SimpleStore", bytecode=bytecode, abi=abi)

    txn = (
        client.deploy_contract('TGQgfK497YXmjdgvun9Bg5Zu3xE15v17cu', cntr)
        .fee_limit(1_000_000)
        .build()
        .sign(priv_key)
        .inspect()
        .broadcast()
    )
    print(txn)
    result = txn.wait()
    print(result)
    print('Created:', result['contract_address'])
