import hashlib
import importlib

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends.openssl.backend import backend

from tronpy.exceptions import BadKey, BadSignature
from tronpy.hdwallet import TRON_DEFAULT_PATH, generate_mnemonic, key_from_seed, seed_from_mnemonic
from tronpy.hdwallet._utils import ec_point
from tronpy.keys import (
    BaseKey,
    PrivateKey,
    PublicKey,
    Signature,
    _secp256k1,
    hash_message,
    keccak256,
    to_base58check_address,
)

SECP256K1_P = 2**256 - 2**32 - 977
SECP256K1_N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
GENERATOR_X = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
GENERATOR_Y = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
NEGATED_GENERATOR_Y = "b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777"
ZERO_DIGEST = bytes(32)
SIGNING_KEY = PrivateKey(b"\x01" * 32)
SIGNED_DIGEST = hashlib.sha256((0).to_bytes(4, "big")).digest()
SIGNED_DIGEST_SIGNATURE = Signature.fromhex(
    "544677df3a29dc2251f2aa1e3e4050a58b645f863f21a8418998f35e5814e668"
    "77ec0968fce695363e4e7bd74d9913bb0f50bbe87849727f97857e6d2ddb207600"
)


def build_signature(r: int, s: int, v: int) -> Signature:
    return Signature(r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([v]))


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

    recovered_address = signature.recover_public_key_from_msg_hash(hashlib.sha256(raw_data).digest()).to_base58check_address()
    assert address == recovered_address


def test_signature_verify(signature, txid, raw_data, pub_key):
    assert signature.verify_msg_hash(txid, pub_key)
    assert signature.verify_msg_hash(hashlib.sha256(raw_data).digest(), pub_key)


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


def test_signature_vectors_for_fixed_key():
    combined = hashlib.sha256()
    for i in range(300):
        digest = hashlib.sha256(i.to_bytes(4, "big")).digest()
        signature = SIGNING_KEY.sign_msg_hash(digest)
        recovered = signature.recover_public_key_from_msg_hash(digest)
        assert recovered == SIGNING_KEY.public_key
        assert signature.verify_msg_hash(digest, recovered) is True
        combined.update(signature.to_bytes() + b"\x04" + recovered.to_bytes())
    assert combined.hexdigest() == "37b67a4b15f9d39dca378a3cf5e6bf52c303d2f312ca8dee00332fb807b199b8"


@pytest.mark.parametrize(
    ("digest", "expected"),
    [
        (
            ZERO_DIGEST,
            "6734cb4e3c071082482bf0f8579484f28dcdb1ca15b0cce72fbf130b2673d00c"
            "5fbeecc4075cfd6a52634210486f24ce6db20f2870e606acc43ade814d48394a00",
        ),
        (
            SECP256K1_N.to_bytes(32, "big"),
            "6734cb4e3c071082482bf0f8579484f28dcdb1ca15b0cce72fbf130b2673d00c"
            "5fbeecc4075cfd6a52634210486f24ce6db20f2870e606acc43ade814d48394a00",
        ),
        (
            SECP256K1_P.to_bytes(32, "big"),
            "7b8059a5092e4f4bb679e46fcc29e5bb8ca95d390e59274d8d09ef5a858d063f"
            "2cfa364b8ac641432a37ddbae381b93ddb46b41740f156d82993132510b7a52d00",
        ),
        (
            b"\xff" * 32,
            "1b3e4eb79d6c3ff54ed5a83dc3e0476abeb3a9488d721c0ee057f48ae17a873c"
            "7a6086244f54c15be735d8b3d5d2ca49106175b061491033c8e6dfa7f93eac9500",
        ),
    ],
    ids=["zero", "n", "p", "max"],
)
def test_signature_vectors_for_edge_digests(digest, expected):
    signature = SIGNING_KEY.sign_msg_hash(digest)
    assert signature.hex() == expected
    assert signature.recover_public_key_from_msg_hash(digest) == SIGNING_KEY.public_key
    assert signature.verify_msg_hash(digest, SIGNING_KEY.public_key) is True


def test_signature_is_low_s():
    assert SIGNED_DIGEST_SIGNATURE.s <= SECP256K1_N // 2
    assert SIGNING_KEY.sign_msg_hash(SIGNED_DIGEST) == SIGNED_DIGEST_SIGNATURE


def test_verify_accepts_high_s():
    signature = SIGNED_DIGEST_SIGNATURE
    high_s = build_signature(signature.r, SECP256K1_N - signature.s, signature.v ^ 1)
    assert high_s.verify_msg_hash(SIGNED_DIGEST, SIGNING_KEY.public_key) is True
    assert high_s.recover_public_key_from_msg_hash(SIGNED_DIGEST) == SIGNING_KEY.public_key


@pytest.mark.parametrize(
    ("r", "s"),
    [
        (0, SIGNED_DIGEST_SIGNATURE.s),
        (SIGNED_DIGEST_SIGNATURE.r, 0),
        (0, 0),
        (SECP256K1_N, SIGNED_DIGEST_SIGNATURE.s),
        (SIGNED_DIGEST_SIGNATURE.r, SECP256K1_N),
        (2**256 - 1, SIGNED_DIGEST_SIGNATURE.s),
        (SIGNED_DIGEST_SIGNATURE.r, 2**256 - 1),
        (SIGNED_DIGEST_SIGNATURE.r, SECP256K1_N + 1),
    ],
    ids=["r=0", "s=0", "r=s=0", "r=n", "s=n", "r=max", "s=max", "s=n+1"],
)
def test_verify_rejects_out_of_range_signature(r, s):
    assert build_signature(r, s, 0).verify_msg_hash(SIGNED_DIGEST, SIGNING_KEY.public_key) is False


def test_verify_rejects_wrong_digest_and_wrong_key():
    signature = SIGNED_DIGEST_SIGNATURE
    assert signature.verify_msg_hash(ZERO_DIGEST, SIGNING_KEY.public_key) is False
    assert signature.verify_msg_hash(SIGNED_DIGEST, PrivateKey(b"\x02" * 32).public_key) is False


@pytest.mark.parametrize(
    "public_key",
    [bytes(64), b"\xff" * 64, (1).to_bytes(32, "big") * 2],
    ids=["zero", "above-field", "off-curve"],
)
def test_verify_raises_on_invalid_public_key(public_key):
    with pytest.raises(ValueError):
        SIGNED_DIGEST_SIGNATURE.verify_msg_hash(SIGNED_DIGEST, PublicKey(public_key))


@pytest.mark.parametrize(
    ("r", "s"),
    [
        (0, SIGNED_DIGEST_SIGNATURE.s),
        (SIGNED_DIGEST_SIGNATURE.r, 0),
        (SECP256K1_N, SIGNED_DIGEST_SIGNATURE.s),
        (SIGNED_DIGEST_SIGNATURE.r, SECP256K1_N),
        (5, SIGNED_DIGEST_SIGNATURE.s),
    ],
    ids=["r=0", "s=0", "r=n", "s=n", "r-not-on-curve"],
)
def test_recover_raises_bad_signature(r, s):
    with pytest.raises(BadSignature):
        build_signature(r, s, 0).recover_public_key_from_msg_hash(SIGNED_DIGEST)


def test_recover_raises_bad_signature_at_infinity():
    nonce = 99
    nonce_point = PrivateKey(nonce.to_bytes(32, "big")).public_key
    r = int.from_bytes(nonce_point[:32], "big")
    y = int.from_bytes(nonce_point[32:], "big")
    with pytest.raises(BadSignature):
        build_signature(r, 5, y & 1).recover_public_key_from_msg_hash((5 * nonce).to_bytes(32, "big"))


@pytest.mark.parametrize("v", [0, 1])
def test_recover_with_edge_scalars(v):
    nonce_point = PrivateKey((99).to_bytes(32, "big")).public_key
    r = int.from_bytes(nonce_point[:32], "big")
    same_point = build_signature(r, r, v).recover_public_key_from_msg_hash(ZERO_DIGEST)
    negated_point = build_signature(r, SECP256K1_N - r, v).recover_public_key_from_msg_hash(ZERO_DIGEST)
    assert same_point[:32] == negated_point[:32] == nonce_point[:32]
    assert same_point[63] & 1 == v
    assert negated_point[63] & 1 == v ^ 1


def test_recover_with_wrong_recovery_id():
    signature = SIGNED_DIGEST_SIGNATURE
    wrong = build_signature(signature.r, signature.s, signature.v ^ 1)
    recovered = wrong.recover_public_key_from_msg_hash(SIGNED_DIGEST)
    assert recovered.hex() == (
        "36372b0b2af7b2911b430bbff5d90e567dd3b5423a7e1a7506c1776574b165db"
        "70327871071b97a41db878b4c6bb44c5b549d558993654f1c9efca5f691c55c3"
    )
    assert wrong.verify_msg_hash(SIGNED_DIGEST, recovered) is True
    assert wrong.verify_msg_hash(SIGNED_DIGEST, SIGNING_KEY.public_key) is True


def test_recover_rejects_recovery_id_outside_signature_range():
    signature = SIGNED_DIGEST_SIGNATURE.to_bytes()[:64] + b"\x02"
    with pytest.raises(ValueError):
        _secp256k1.recover(signature, SIGNED_DIGEST)


@pytest.mark.parametrize(
    ("digest", "error"),
    [
        (bytes(31), ValueError),
        (bytes(33), ValueError),
        (b"", ValueError),
        ("a" * 31, ValueError),
        ("a" * 32, TypeError),
        (bytearray(32), TypeError),
        (memoryview(bytes(32)), TypeError),
        (None, TypeError),
    ],
    ids=["short", "long", "empty", "str-short", "str", "bytearray", "memoryview", "none"],
)
def test_invalid_message_hash(digest, error):
    with pytest.raises(error):
        SIGNING_KEY.sign_msg_hash(digest)
    with pytest.raises(error):
        SIGNED_DIGEST_SIGNATURE.verify_msg_hash(digest, SIGNING_KEY.public_key)
    with pytest.raises(BadSignature):
        SIGNED_DIGEST_SIGNATURE.recover_public_key_from_msg_hash(digest)


@pytest.mark.parametrize(
    ("value", "y", "compressed_prefix"),
    [(1, GENERATOR_Y, "02"), (SECP256K1_N - 1, NEGATED_GENERATOR_Y, "03")],
    ids=["1", "n-1"],
)
def test_valid_key_bounds(value, y, compressed_prefix):
    raw_key = value.to_bytes(32, "big")
    assert PrivateKey(raw_key).public_key.hex() == GENERATOR_X + y
    assert ec_point(raw_key).hex() == compressed_prefix + GENERATOR_X
    signature = PrivateKey(raw_key).sign_msg_hash(SIGNED_DIGEST)
    assert signature.recover_public_key_from_msg_hash(SIGNED_DIGEST) == PrivateKey(raw_key).public_key


@pytest.mark.parametrize("value", [0, SECP256K1_N, SECP256K1_N + 1, 2**256 - 1], ids=["0", "n", "n+1", "max"])
def test_invalid_key_bounds(value):
    raw_key = value.to_bytes(32, "big")
    with pytest.raises(BadKey):
        PrivateKey(raw_key)
    with pytest.raises(ValueError):
        ec_point(raw_key)


def test_hd_vector():
    pytest.importorskip("mnemonic")
    seed = seed_from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", ""
    )
    private_key = PrivateKey(key_from_seed(seed, TRON_DEFAULT_PATH))
    assert private_key.public_key.to_base58check_address() == "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"


def test_mnemonic_extra_missing(monkeypatch):
    monkeypatch.setattr("tronpy.hdwallet.Mnemonic", None)
    with pytest.raises(ImportError, match=r"tronpy\[mnemonic\]"):
        generate_mnemonic(12, "english")
    with pytest.raises(ImportError, match=r"tronpy\[mnemonic\]"):
        seed_from_mnemonic("abandon about", "")


def test_signing_refuses_unmatched_recovery_id(monkeypatch):
    monkeypatch.setattr(_secp256k1, "_recover_point", lambda *_: (1, 1))
    with pytest.raises(ValueError):
        SIGNING_KEY.sign_msg_hash(SIGNED_DIGEST)


def test_only_signing_needs_deterministic_support(monkeypatch):
    monkeypatch.setattr(backend, "ecdsa_deterministic_supported", lambda: False)
    importlib.reload(_secp256k1)
    assert PrivateKey(b"\x01" * 32).public_key == SIGNING_KEY.public_key
    assert SIGNED_DIGEST_SIGNATURE.verify_msg_hash(SIGNED_DIGEST, SIGNING_KEY.public_key) is True
    assert SIGNED_DIGEST_SIGNATURE.recover_public_key_from_msg_hash(SIGNED_DIGEST) == SIGNING_KEY.public_key
    with pytest.raises(UnsupportedAlgorithm):
        SIGNING_KEY.sign_msg_hash(SIGNED_DIGEST)


def test_base_key_cannot_be_instantiated():
    with pytest.raises(TypeError, match="abstract"):
        BaseKey()
    with pytest.raises(TypeError, match="abstract"):
        BaseKey(b"\x01" * 32)
    with pytest.raises(TypeError, match="abstract"):
        BaseKey.fromhex("01" * 32)


@pytest.mark.parametrize("key_class, raw", [(PrivateKey, b"\x01" * 32), (PublicKey, b"\x01" * 64)])
def test_fromhex_returns_own_class(key_class, raw):
    key = key_class.fromhex(raw.hex())
    assert type(key) is key_class
    assert key.to_bytes() == raw
