import pytest
from eth_abi.exceptions import EncodingTypeError, NoEntriesFound, NonEmptyPaddingBytes, ValueOutOfBounds

from tronpy.abi import trx_abi

TRC_TOKEN_ID = 1000001
ENCODED_TRC_TOKEN_ID = "00000000000000000000000000000000000000000000000000000000000f4241"


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


def test_abi_trc_token():
    data = bytes.fromhex(ENCODED_TRC_TOKEN_ID)
    assert trx_abi.encode_abi(["trcToken"], [TRC_TOKEN_ID]) == data
    assert trx_abi.encode_single("trcToken", TRC_TOKEN_ID) == data
    assert trx_abi.encode_abi(["trcToken"], [TRC_TOKEN_ID]) == trx_abi.encode_abi(["uint256"], [TRC_TOKEN_ID])
    assert trx_abi.decode_abi(["trcToken"], data) == (TRC_TOKEN_ID,)
    assert trx_abi.decode_single("trcToken", data) == TRC_TOKEN_ID


def test_abi_trc_token_in_composite_types():
    address = "TLfuw4tRywtxCusvTudbjf7PbcXjfe7qrw"
    encoded_address = "0000000000000000000000007564105e977516c53be337314c7e53838967bdac"
    tuple_data = bytes.fromhex(encoded_address + ENCODED_TRC_TOKEN_ID)
    assert trx_abi.encode_single("(address,trcToken)", [address, TRC_TOKEN_ID]) == tuple_data
    assert trx_abi.decode_single("(address,trcToken)", tuple_data) == (address, TRC_TOKEN_ID)

    array_data = trx_abi.encode_single("trcToken[]", [TRC_TOKEN_ID])
    assert array_data == trx_abi.encode_single("uint256[]", [TRC_TOKEN_ID])
    assert trx_abi.decode_single("trcToken[]", array_data) == (TRC_TOKEN_ID,)


@pytest.mark.parametrize(
    ("value", "error"),
    [(-1, ValueOutOfBounds), (2**256, ValueOutOfBounds), ("1000001", EncodingTypeError)],
)
def test_abi_trc_token_rejects_invalid_values(value, error):
    with pytest.raises(error):
        trx_abi.encode_single("trcToken", value)


def test_abi_trc_token_rejects_size_suffix():
    with pytest.raises(NoEntriesFound):
        trx_abi.encode_single("trcToken8", TRC_TOKEN_ID)
