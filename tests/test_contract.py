from tronpy import Tron
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
        .call('TJRabPrwbZy45sbavfcjinPJC18kjpRTv8', 1_000_000)
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
