"""secp256k1 on top of OpenSSL. Only public values go through Python arithmetic: the key is handed to OpenSSL as is."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

P = 2**256 - 2**32 - 977
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337

_CURVE = ec.SECP256K1()
_PREHASHED = Prehashed(hashes.SHA256())

Point = tuple[int, int]


def _private_key(raw_key: bytes) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(raw_key, "big"), _CURVE)


def public_key_bytes(raw_key: bytes) -> bytes:
    return _private_key(raw_key).public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)[1:]


def compressed_public_key_bytes(raw_key: bytes) -> bytes:
    return _private_key(raw_key).public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def _check_digest(message_hash: bytes) -> None:
    if len(message_hash) != 32:
        raise ValueError("Message hash must be 32 bytes long.")
    if not isinstance(message_hash, bytes):
        raise TypeError("Message hash must be bytes.")


def _add(a: Point | None, b: Point | None) -> Point | None:
    if a is None or b is None:
        return a or b
    if a[0] == b[0]:
        if (a[1] + b[1]) % P == 0:
            return None
        slope = 3 * a[0] * a[0] * pow(2 * a[1], -1, P)
    else:
        slope = (b[1] - a[1]) * pow(b[0] - a[0], -1, P)
    x = (slope * slope - a[0] - b[0]) % P
    return x, (slope * (a[0] - x) - a[1]) % P


def _lift_x(x: int) -> int:
    square = (pow(x, 3, P) + 7) % P
    y = pow(square, (P + 1) // 4, P)
    if y * y % P != square:
        raise ValueError("Not a curve point")
    return y


def _mul_base(scalar: int) -> Point | None:
    if scalar == 0:
        return None
    numbers = ec.derive_private_key(scalar, _CURVE).public_key().public_numbers()
    return numbers.x, numbers.y


def _x_of_product(scalar: int, peer: ec.EllipticCurvePublicKey) -> int:
    return int.from_bytes(ec.derive_private_key(scalar, _CURVE).exchange(ec.ECDH(), peer), "big")


def _mul(scalar: int, point: Point) -> Point:
    """Multiply public values: ECDH yields only x, so x((k + 1)P) selects the y that satisfies kP + P."""
    if scalar == N - 1:
        return point[0], P - point[1]
    peer = ec.EllipticCurvePublicNumbers(point[0], point[1], _CURVE).public_key()
    x = _x_of_product(scalar, peer)
    y = _lift_x(x)
    following = _add((x, y), point)
    if following is not None and following[0] == _x_of_product(scalar + 1, peer):
        return x, y
    return x, P - y


def _recover_point(r: int, s: int, v: int, message_hash: bytes) -> Point:
    if not (0 < r < N and 0 < s < N) or v not in (0, 1):
        raise ValueError("Invalid signature")
    y = _lift_x(r)
    if y & 1 != v:
        y = P - y
    r_inverse = pow(r, -1, N)
    z = int.from_bytes(message_hash, "big")
    recovered = _add(_mul_base(-z * r_inverse % N), _mul(s * r_inverse % N, (r, y)))
    if recovered is None:
        raise ValueError("Invalid signature")
    return recovered


def recover(signature: bytes, message_hash: bytes) -> bytes:
    _check_digest(message_hash)
    r, s, v = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:64], "big"), signature[64]
    x, y = _recover_point(r, s, v, message_hash)
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")


def sign_recoverable(raw_key: bytes, message_hash: bytes) -> bytes:
    _check_digest(message_hash)
    private_key = _private_key(raw_key)
    signature = private_key.sign(message_hash, ec.ECDSA(_PREHASHED, deterministic_signing=True))
    r, s = decode_dss_signature(signature)
    s = min(s, N - s)
    numbers = private_key.public_key().public_numbers()
    for v in (0, 1):
        if _recover_point(r, s, v, message_hash) == (numbers.x, numbers.y):
            return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([v])
    raise ValueError("Could not determine recovery id")


def verify(r: int, s: int, message_hash: bytes, public_key: bytes) -> bool:
    key = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, b"\x04" + public_key)
    _check_digest(message_hash)
    try:
        key.verify(encode_dss_signature(r, s), message_hash, ec.ECDSA(_PREHASHED))
    except InvalidSignature:
        return False
    return True
