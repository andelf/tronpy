from tronpy.abi import trx_abi


def test_abi_encode():
    assert (
        trx_abi.encode_single("address", "TLfuw4tRywtxCusvTudbjf7PbcXjfe7qrw").hex()
        == '0000000000000000000000007564105e977516c53be337314c7e53838967bdac'
    )

    assert trx_abi.encode_single("(address,uint256)", ["TLfuw4tRywtxCusvTudbjf7PbcXjfe7qrw", 100_000_000]).hex() == (
        '0000000000000000000000007564105e977516c53be337314c7e53838967bdac'
        + '0000000000000000000000000000000000000000000000000000000005f5e100'
    )


def test_abi_decode():
    assert trx_abi.decode_abi(
        ['address', 'uint256'],
        bytes.fromhex(
            '0000000000000000000000007564105e977516c53be337314c7e53838967bdac'
            + '0000000000000000000000000000000000000000000000000000000005f5e100'
        ),
    ) == ('TLfuw4tRywtxCusvTudbjf7PbcXjfe7qrw', 100000000)
