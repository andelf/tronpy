import hashlib
import os
from collections.abc import Hashable, Iterator, Sequence
from typing import Any, Union

import base58
from coincurve import PrivateKey as CoincurvePrivateKey
from coincurve import PublicKey as CoincurvePublicKey
from Crypto.Hash import keccak

from tronpy.exceptions import BadAddress, BadKey, BadSignature

SECPK1_N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
TRON_MESSAGE_PREFIX = "\x19TRON Signed Message:\n"


def coerce_low_s(value: int) -> int:
    """Coerce the s component of an ECDSA signature into its low-s form.
    See https://bitcoin.stackexchange.com/questions/83408/in-ecdsa-why-is-r-%E2%88%92s-mod-n-complementary-to-r-s
    """
    return min(value, -value % SECPK1_N)


def two_int_sequence_encoder(signature_r: int, signature_s: int) -> Iterator[int]:
    # Sequence tag
    yield 0x30

    encoded1 = bytes(_encode_int(signature_r))
    encoded2 = bytes(_encode_int(signature_s))

    # Sequence length
    yield len(encoded1) + len(encoded2)

    yield from encoded1
    yield from encoded2


def int_to_big_endian(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")


def _encode_int(primitive: int) -> Iterator[int]:
    # Integer tag
    yield 0x02

    encoded = int_to_big_endian(primitive)
    if encoded[0] >= 128:
        # Indicate that integer is positive (it always is, but doesn't always need the flag)
        yield len(encoded) + 1
        yield 0x00
    else:
        yield len(encoded)

    yield from encoded


def keccak256(data: bytes) -> bytes:
    hasher = keccak.new(digest_bits=256)
    hasher.update(data)
    return hasher.digest()


def sha256(data: bytes) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.digest()


def public_key_to_base58check_addr(pub_key: bytes) -> str:
    primitive_addr = b"\x41" + keccak256(pub_key)[-20:]
    addr = base58.b58encode_check(primitive_addr)
    return addr.decode()


def public_key_to_addr(pub_key: bytes) -> bytes:
    return b"\x41" + keccak256(pub_key)[-20:]


def to_base58check_address(raw_addr: Union[str, bytes]) -> str:
    """Convert hex address or base58check address to base58check address(and verify it)."""
    if isinstance(raw_addr, (str,)):
        if raw_addr[0] == "T" and len(raw_addr) == 34:
            try:
                # assert checked
                base58.b58decode_check(raw_addr)
            except ValueError as e:
                raise BadAddress("bad base58check format") from e
            return raw_addr
        if len(raw_addr) == 42:
            if raw_addr.startswith("0x"):  # eth address format
                return base58.b58encode_check(b"\x41" + bytes.fromhex(raw_addr[2:])).decode()
            return base58.b58encode_check(bytes.fromhex(raw_addr)).decode()
        if raw_addr.startswith("0x") and len(raw_addr) == 44:
            return base58.b58encode_check(bytes.fromhex(raw_addr[2:])).decode()
    elif isinstance(raw_addr, (bytes, bytearray)):
        if len(raw_addr) == 21 and int(raw_addr[0]) == 0x41:
            return base58.b58encode_check(raw_addr).decode()
        if len(raw_addr) == 20:  # eth address format
            return base58.b58encode_check(b"\x41" + raw_addr).decode()
        return to_base58check_address(raw_addr.decode())
    raise BadAddress(repr(raw_addr))


def to_hex_address(raw_addr: Union[str, bytes]) -> str:
    addr = to_base58check_address(raw_addr)
    return base58.b58decode_check(addr).hex()


def to_raw_address(raw_addr: Union[str, bytes]) -> bytes:
    addr = to_base58check_address(raw_addr)
    return base58.b58decode_check(addr)


def to_tvm_address(raw_addr: Union[str, bytes]) -> bytes:
    return to_raw_address(raw_addr)[1:]


def is_base58check_address(value: str) -> bool:
    return value[0] == "T" and len(base58.b58decode_check(value)) == 21


def is_hex_address(value: str) -> bool:
    return value.startswith("41") and len(bytes.fromhex(value)) == 21


def is_address(value: str) -> bool:
    return is_base58check_address(value) or is_hex_address(value)


def hash_message(message):
    if isinstance(message, str):
        message = message.encode()
    message_length = str(len(message)).encode()
    return keccak256(TRON_MESSAGE_PREFIX.encode() + message_length + message)


class BaseKey(Sequence, Hashable):
    _raw_key = None  # type: bytes

    # compatible with bytes.hex()
    def hex(self) -> str:
        """
        Key as a hex str.

        :returns: A hex str.
        """
        return self._raw_key.hex()

    @classmethod
    def fromhex(cls, hex_str: str) -> "BaseKey":
        """
        Construct a key from a hex str.

        :returns: The key object.
        """
        return cls(bytes.fromhex(hex_str))

    def to_bytes(self) -> bytes:
        return self._raw_key

    def __hash__(self) -> int:
        return int.from_bytes(self._raw_key, "big")

    def __str__(self) -> str:
        return self.hex()

    def __int__(self) -> int:
        return int.from_bytes(self._raw_key, "big")

    def __len__(self) -> int:
        return len(self._raw_key)

    # Must be typed with `ignore` due to
    # https://github.com/python/mypy/issues/1237
    def __getitem__(self, index: int) -> int:  # type: ignore
        return self._raw_key[index]

    def __eq__(self, other: Any) -> bool:
        if hasattr(other, "to_bytes"):
            return self.to_bytes() == other.to_bytes()
        if isinstance(other, (bytes, bytearray)):
            return self.to_bytes() == other
        return False

    def __repr__(self) -> str:
        return repr(self.hex())

    def __index__(self) -> int:
        return self.__int__()

    def __hex__(self) -> str:
        return self.hex()


class PublicKey(BaseKey):
    """The public key."""

    def __init__(self, public_key_bytes: bytes):
        if not isinstance(public_key_bytes, (bytes,)):
            raise BadKey("public_key_bytes must be bytes")
        if len(public_key_bytes) != 64:
            raise BadKey(f"public_key_bytes must be 64 bytes long, got {len(public_key_bytes)}")

        self._raw_key = public_key_bytes

        super().__init__()

    @classmethod
    def recover_from_msg(cls, message: bytes, signature: "Signature"):
        """Recover public key(address) from raw message and signature."""
        return signature.recover_public_key_from_msg(message)

    @classmethod
    def recover_from_msg_hash(cls, message_hash: bytes, signature: "Signature"):
        """Recover public key(address) from message hash and signature."""
        return signature.recover_public_key_from_msg_hash(message_hash)

    def verify_msg(self, message: bytes, signature: "Signature") -> bool:
        """Verify message and signature."""
        return signature.verify_msg(message, self)

    def verify_msg_hash(self, message_hash: bytes, signature: "Signature") -> bool:
        """Verify message hash and signature."""
        return signature.verify_msg_hash(message_hash, self)

    # Address conversions
    def to_base58check_address(self) -> str:
        """Get the base58check address of the public key."""
        return public_key_to_base58check_addr(self._raw_key)

    def to_hex_address(self) -> str:
        return public_key_to_addr(self._raw_key).hex()

    def to_address(self) -> bytes:
        return public_key_to_addr(self._raw_key)

    def to_tvm_address(self) -> bytes:
        return public_key_to_addr(self._raw_key)[1:]


class PrivateKey(BaseKey):
    """The private key."""

    public_key = None

    def __init__(self, private_key_bytes: bytes):
        if not isinstance(private_key_bytes, (bytes,)):
            raise BadKey("private_key_bytes must be bytes")
        if len(private_key_bytes) != 32:
            raise BadKey(f"private_key_bytes must be 32 bytes long, got {len(private_key_bytes)}")
        if not (
            0
            < int.from_bytes(private_key_bytes, "big")
            < 115792089237316195423570985008687907852837564279074904382605163141518161494337
        ):
            raise BadKey("private key is not in the valid range")

        self._raw_key = private_key_bytes

        priv_key = CoincurvePrivateKey(self._raw_key)
        self.public_key = PublicKey(priv_key.public_key.format(compressed=False)[1:])

        super().__init__()

    def sign_msg(self, message: bytes) -> "Signature":
        """Sign a raw message."""
        message_hash = hash_message(message)
        return self.sign_msg_hash(message_hash)

    def sign_msg_hash(self, message_hash: bytes) -> "Signature":
        """Sign a message hash."""
        private_key_bytes = self.to_bytes()
        signature_bytes = CoincurvePrivateKey(private_key_bytes).sign_recoverable(
            message_hash,
            hasher=None,
        )
        return Signature(signature_bytes)

    @classmethod
    def random(cls) -> "PrivateKey":
        """Generate a random private key."""
        return cls(os.urandom(32))

    @classmethod
    def from_passphrase(cls, passphrase: bytes) -> "PrivateKey":
        """Get a private key from sha256 of a passphrase."""
        return cls(sha256(passphrase))


class Signature(Sequence):
    """The signature object."""

    _raw_signature = None

    def __init__(self, signature_bytes: bytes):
        if not isinstance(signature_bytes, (bytes,)):
            raise BadSignature("signature_bytes must be bytes")

        if len(signature_bytes) != 65:
            raise BadSignature(f"signature_bytes must be 65 bytes long, got {len(signature_bytes)}")

        signature_bytes = signature_bytes[:64] + bytes([self.normalize_v(signature_bytes[-1])])

        self._raw_signature = signature_bytes

        super().__init__()

    def normalize_v(self, v: int) -> int:
        if v in (0, 27):
            return 0
        if v in (1, 28):
            return 1
        if v < 35:
            raise BadSignature(f"invalid v {v}")
        return int(v % 2 != 1)

    def recover_public_key_from_msg(self, message: bytes) -> PublicKey:
        """Recover public key(address) from message and signature."""
        message_hash = hash_message(message)
        return self.recover_public_key_from_msg_hash(message_hash)

    def recover_public_key_from_msg_hash(self, message_hash: bytes) -> PublicKey:
        """Recover public key(address) from message hash and signature."""
        signature_bytes = self.to_bytes()
        try:
            public_key_bytes = CoincurvePublicKey.from_signature_and_message(
                signature_bytes,
                message_hash,
                hasher=None,
            ).format(compressed=False)[1:]
        except (ValueError, Exception) as err:
            # `coincurve` can raise `ValueError` or `Exception` dependending on
            # how the signature is invalid.
            raise BadSignature(str(err)) from err
        return PublicKey(public_key_bytes)

    def verify_msg(self, message: bytes, public_key: PublicKey) -> bool:
        """Verify message and signature."""
        message_hash = hash_message(message)
        return self.verify_msg_hash(message_hash, public_key)

    def verify_msg_hash(self, message_hash: bytes, public_key: PublicKey) -> bool:
        """Verify message hash and signature."""
        # coincurve rejects signatures with a high s, so convert to the equivalent low s form
        low_s = coerce_low_s(self.s)
        der_encoded_signature = bytes(two_int_sequence_encoder(self.r, low_s))
        coincurve_public_key = CoincurvePublicKey(b"\x04" + public_key.to_bytes())
        return coincurve_public_key.verify(
            der_encoded_signature,
            message_hash,
            hasher=None,
        )

    @property
    def r(self) -> int:
        return int.from_bytes(self._raw_signature[:32], "big")

    @property
    def s(self) -> int:
        return int.from_bytes(self._raw_signature[32:64], "big")

    @property
    def v(self) -> int:
        return self._raw_signature[64]

    def hex(self) -> str:
        """
        Return signature as a hex str.

        :returns: A hex str.
        """
        return self._raw_signature.hex()

    def tronweb_hex(self) -> str:
        """Return signature as a hex str in TronWeb format (v+27)."""
        r = hex(self.r)[2:].zfill(64)
        s = hex(self.s)[2:].zfill(64)
        v = self.v + 27
        return r + s + f"{v:02x}"

    @classmethod
    def fromhex(cls, hex_str: str) -> "Signature":
        """Construct a Signature from hex str."""
        return cls(bytes.fromhex(hex_str))

    def to_bytes(self) -> bytes:
        return self._raw_signature

    def __hash__(self) -> int:
        return int.from_bytes(self._raw_signature, "big")

    def __str__(self) -> str:
        return self.hex()

    def __int__(self) -> int:
        return int.from_bytes(self._raw_signature, "big")

    def __len__(self) -> int:
        return 65

    def __getitem__(self, index: int) -> int:  # type: ignore
        return self._raw_signature[index]

    def __eq__(self, other: Any) -> bool:
        if hasattr(other, "to_bytes"):
            return self.to_bytes() == other.to_bytes()
        if isinstance(other, (bytes, bytearray)):
            return self.to_bytes() == other
        return False

    def __repr__(self) -> str:
        return repr(self.hex())

    def __index__(self) -> int:
        return self.__int__()

    def __hex__(self) -> str:
        return self.hex()


__all__ = [
    "PrivateKey",
    "PublicKey",
    "Signature",
    "to_base58check_address",
    "to_hex_address",
    "to_tvm_address",
    "is_address",
    "is_base58check_address",
    "is_hex_address",
    "hash_message",
    "sha256",
    "keccak256",
]
