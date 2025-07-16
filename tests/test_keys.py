import pytest

from tronpy.exceptions import BadKey
from tronpy.keys import PrivateKey, PublicKey, Signature, hash_message, keccak256, sha256, to_base58check_address

# https://shasta.tronscan.org/#/transaction/17821228a79904c23bd35e566f320c2d43e6940c0d44bc8d70f257f3485459bb


@pytest.fixture
def txid():
    return bytes.fromhex("17821228a79904c23bd35e566f320c2d43e6940c0d44bc8d70f257f3485459bb")


@pytest.fixture
def raw_data():
    return bytes.fromhex(
        "0a026ecf22083c083e47cbea43ec40f8dfe182a82e520302c75f5a66080112620a2d7479"
        "70652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e7366657243"
        "6f6e747261637412310a15419cf784b4cc7531f1598c4c322de9afdc597fe76012154134"
        "0967e825557559dc46bbf0eabe5ccf99fd134e18e80770f5a2de82a82e"
    )


@pytest.fixture
def pub_key():
    return PublicKey.fromhex(
        "56f19ba7de92264d94f9b6600ec05c16c0b25a064e2ee1cf5bf0dd9661d04515c99c3a6b"
        "42b2c574232a5b951bf57cf706bbfd36377b406f9313772f65612cd0"
    )


@pytest.fixture
def signature():
    return Signature.fromhex(
        "c4cfe5c76bf89fe004ff59de1a33934a9419301e21fbe1f00ee5b5faf17189797a7292e8"
        "72a693e7bff145e76c43ea6f26c425be70d0e0d0440331390d0d65a401"
    )


@pytest.fixture
def address():
    return "TQHAvs2ZFTbsd93ycTfw1Wuf1e4WsPZWCp"


def test_private_key():
    with pytest.raises(BadKey):
        PrivateKey(bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"))


def test_public_key():
    key = PublicKey.fromhex("00" * 64)
    assert key.hex() == "00" * 64


def test_key_convert():
    priv_key = PrivateKey.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
    assert priv_key.hex() == "0000000000000000000000000000000000000000000000000000000000000001"


def test_signature_recover(signature, txid, address, raw_data):
    recovered_address = signature.recover_public_key_from_msg_hash(txid).to_base58check_address()
    assert address == recovered_address

    recovered_address = signature.recover_public_key_from_msg_hash(sha256(raw_data)).to_base58check_address()
    assert address == recovered_address


def test_signature_verify(signature, txid, raw_data, pub_key):
    assert signature.verify_msg_hash(txid, pub_key)
    assert signature.verify_msg_hash(sha256(raw_data), pub_key)


def test_signature_sign(signature: Signature, raw_data: bytes, txid: bytes):
    priv_key = PrivateKey.fromhex("0000000000000000000000000000000000000000000000000000000000000001")

    sig = priv_key.sign_msg(raw_data)
    pub_key = sig.recover_public_key_from_msg(raw_data)
    assert priv_key.public_key == pub_key

    sig = priv_key.sign_msg_hash(txid)
    pub_key = sig.recover_public_key_from_msg_hash(txid)
    assert priv_key.public_key == pub_key


def test_key_derivation():
    priv_key = PrivateKey.fromhex("279ff36d9bf9f305af3280034bb4187c6dd299bac6b26a3c20b999c7c0d50e6e")
    assert priv_key.hex() == "279ff36d9bf9f305af3280034bb4187c6dd299bac6b26a3c20b999c7c0d50e6e"
    public_key = priv_key.public_key
    assert (
        public_key.hex() == "cc0402d331f2bb4482e43825d66f2963e6de9bac0033933cdccef20d9a0d737e8f4e2c97"
        "e14d6ef7d50ca0d8ee94094d3fa0ef08ae45d1b5409a0c92dd0f8c44"
    )
    assert public_key.to_base58check_address() == "TPX6HK2NRN4XKRX1JAhbC827bm7gMmy5w1"
    assert public_key.to_hex_address() == "4194a15629b2b2bbd3a5453e6d6696b2875278633b"


def test_to_base58check_address():
    assert (
        to_base58check_address("410000000000000000000000000000000000000000")
        == to_base58check_address("T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb")
        == to_base58check_address(bytes.fromhex("410000000000000000000000000000000000000000"))
        == to_base58check_address("0x0000000000000000000000000000000000000000")
    )


def arrayify(hex_string):
    if isinstance(hex_string, (bytes, bytearray)):
        return hex_string
    if hex_string.startswith("0x"):
        return bytes.fromhex(hex_string[2:])
    return bytes.fromhex(hex_string)


tronweb_signature_tests = [
    {
        "address": "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC",
        "name": 'string("hello world")',
        "message": "hello world",
        "messageHash": "0xcf02daeb2bea196ed5692322a66ed50080ce74ff8cb711199f1b04f3c13bc10d",
        "privateKey": "0000000000000000000000000000000000000000000000000000000000000001",
        "signature": (
            "0x0dc0b53d525e0103a6013061cf18e60cf158809149f2b8994a545af65a7004cb"
            "1eeaff560e801ab51b28df5d42549aa024c2aa7e9d34de1e01294b9afb5e6c7e1c"
        ),
    },
    {
        "address": "TVEZYjZyemfJoLUdGtzsM2ua1HAnbsNgAF",
        "name": "bytes(0x47173285...4cb01fad)",
        "message": arrayify("0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"),
        "messageHash": "0x66733cf31ee3f133db9561efdca3d65ba930bdf57fb1af3b6cc0ba4966ecc882",
        "privateKey": "51d1d6047622bca92272d36b297799ecc152dc2ef91b229debf84fc41e8c73ee",
        "signature": (
            "0xdc3ffce3ffa792a3c76b9ea6909f715ffed0386bb9be0d1ece2d80bde37c3680"
            "28eed4c9a6fd9608407b224050db7c648a8a7668a7582893efcb2c19d3327b811b"
        ),
    },
    {
        "address": "TBzEvowPVErmNWVegYMQcurDF3jgHU4VME",
        "name": "zero-prefixed signature",
        "message": arrayify(keccak256(b"0x7f23b5eed5bc7e89f267f339561b2697faab234a2")),
        "messageHash": "0xc6bb689ca3663d132c07540d31f46e03b0e4291d990c77083c136a234f079455",
        "privateKey": "59f40af46420081988724249fb743e7597c8ddc1cbbc0738b96ceb1dbb149373",
        "signature": (
            "0x4a32ec6cfd034304f6fb45767d98a2414a9ab439a829b60e756c79f7e3c0f4ed"
            "0d1f76d88839a4425146084a6ef3703a2a692fdacc76c80c269268f6ba6df38b1c"
        ),
    },
]


@pytest.mark.parametrize("test_case", tronweb_signature_tests, ids=lambda test: test["name"])
def test_tronweb_compatibility(test_case):
    privkey = PrivateKey.fromhex(test_case["privateKey"])
    message = test_case["message"]
    computed_hash = hash_message(message)
    computed_hash_hex = f"0x{computed_hash.hex()}"
    assert computed_hash_hex == test_case["messageHash"], (
        f"Message hash mismatch: expected {test_case['messageHash']}, got {computed_hash_hex}"
    )
    signature = privkey.sign_msg(message)
    computed_signature = f"0x{signature.tronweb_hex()}"
    assert computed_signature == test_case["signature"], (
        f"Signature mismatch: expected {test_case['signature']}, got {computed_signature}"
    )
    recovered_pubkey = signature.recover_public_key_from_msg(message)
    recovered_address = recovered_pubkey.to_base58check_address()
    assert recovered_address == test_case["address"], (
        f"Address mismatch: expected {test_case['address']}, got {recovered_address}"
    )
