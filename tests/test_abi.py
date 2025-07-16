import pytest
from eth_abi.exceptions import NonEmptyPaddingBytes

from tronpy.abi import trx_abi


def test_abi_encode():
    assert (
        trx_abi.encode_single("address", "TLfuw4tRywtxCusvTudbjf7PbcXjfe7qrw").hex()
        == "0000000000000000000000007564105e977516c53be337314c7e53838967bdac"
    )

    assert trx_abi.encode_single("(address,uint256)", ["TLfuw4tRywtxCusvTudbjf7PbcXjfe7qrw", 100_000_000]).hex() == (
        "0000000000000000000000007564105e977516c53be337314c7e53838967bdac"
        + "0000000000000000000000000000000000000000000000000000000005f5e100"
    )


def test_abi_decode():
    assert trx_abi.decode_abi(
        ["address", "uint256"],
        bytes.fromhex(
            "0000000000000000000000007564105e977516c53be337314c7e53838967bdac"
            + "0000000000000000000000000000000000000000000000000000000005f5e100"
        ),
    ) == ("TLfuw4tRywtxCusvTudbjf7PbcXjfe7qrw", 100000000)


def test_abi_decode_non_strict():
    with pytest.raises(NonEmptyPaddingBytes):
        trx_abi.decode_abi(
            ["address", "uint256"],
            bytes.fromhex(
                "000000000001158181d6f2f092399a9df7d1c21ed43b17e1b1709f774f455548"
                + "000000000000000000000000000000000000000000000000000000000bebc200"
            ),
        )
    assert trx_abi.decode_abi(
        ["address", "uint256"],
        bytes.fromhex(
            "000000000001158181d6f2f092399a9df7d1c21ed43b17e1b1709f774f455548"
            + "000000000000000000000000000000000000000000000000000000000bebc200"
        ),
        strict=False,
    ) == ("TPJNfTfBunWWqME2Povh6thCffaUDumkXV", 200000000)
