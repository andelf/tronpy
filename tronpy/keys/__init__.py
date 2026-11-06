import os
from abc import abstractmethod
from collections.abc import Hashable, Sequence
from typing import Any, Self, cast

import base58
from Crypto.Hash import keccak

from tronpy.exceptions import BadAddress, BadKey, BadSignature
from tronpy.keys import _secp256k1

TRON_MESSAGE_PREFIX = "\x19TRON Signed Message:\n"


def keccak256(data: bytes) -> bytes:
    hasher = keccak.new(digest_bits=256)
    hasher.update(data)
    return hasher.digest()


def public_key_to_base58check_addr(pub_key: bytes) -> str:
    primitive_addr = b"\x41" + keccak256(pub_key)[-20:]
    addr = base58.b58encode_check(primitive_addr)
    return addr.decode()


def public_key_to_addr(pub_key: bytes) -> bytes:
    return b"\x41" + keccak256(pub_key)[-20:]


def to_base58check_address(raw_addr: str | bytes) -> str:
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


def to_hex_address(raw_addr: str | bytes) -> str:
    addr = to_base58check_address(raw_addr)
    return base58.b58decode_check(addr).hex()


def to_raw_address(raw_addr: str | bytes) -> bytes:
    addr = to_base58check_address(raw_addr)
    return base58.b58decode_check(addr)


def to_tvm_address(raw_addr: str | bytes) -> bytes:
    return to_raw_address(raw_addr)[1:]


def is_base58check_address(value: str) -> bool:
    return value[0] == "T" and len(base58.b58decode_check(value)) == 21


def is_hex_address(value: str) -> bool:
    return value.startswith("41") and len(bytes.fromhex(value)) == 21


def is_address(value: str) -> bool:
    return is_base58check_address(value) or is_hex_address(value)


def hash_message(message: str | bytes) -> bytes:
    if isinstance(message, str):
        message = message.encode()
    message_length = str(len(message)).encode()
    return keccak256(TRON_MESSAGE_PREFIX.encode() + message_length + message)


class BaseKey(Sequence, Hashable):
    _raw_key: bytes

    @abstractmethod
    def __init__(self, raw_key: bytes) -> None: ...

    # compatible with bytes.hex()
    def hex(self) -> str:
        """
        Key as a hex str.

        :returns: A hex str.
        """
        return self._raw_key.hex()

    @classmethod
    def fromhex(cls, hex_str: str) -> Self:
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
    def __getitem__(self, index: int) -> int:  # type: ignore[override]
        return self._raw_key[index]

    def __eq__(self, other: Any) -> bool:
        if hasattr(other, "to_bytes"):
            return cast(bool, self.to_bytes() == other.to_bytes())
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

    @classmethod
    def recover_from_msg(cls, message: bytes, signature: "Signature") -> "PublicKey":
        """Recover public key(address) from raw message and signature."""
        return signature.recover_public_key_from_msg(message)

    @classmethod
    def recover_from_msg_hash(cls, message_hash: bytes, signature: "Signature") -> "PublicKey":
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

    public_key: PublicKey

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

        self.public_key = PublicKey(_secp256k1.public_key_bytes(self._raw_key))

    def sign_msg(self, message: bytes) -> "Signature":
        """Sign a raw message."""
        message_hash = hash_message(message)
        return self.sign_msg_hash(message_hash)

    def sign_msg_hash(self, message_hash: bytes) -> "Signature":
        """Sign a message hash."""
        return Signature(_secp256k1.sign_recoverable(self.to_bytes(), message_hash))

    @classmethod
    def random(cls) -> "PrivateKey":
        """Generate a random private key."""
        return cls(os.urandom(32))


class Signature(Sequence):
    """The signature object."""

    _raw_signature: bytes

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
        try:
            return PublicKey(_secp256k1.recover(self.to_bytes(), message_hash))
        except (TypeError, ValueError) as err:
            raise BadSignature(str(err)) from err

    def verify_msg(self, message: bytes, public_key: PublicKey) -> bool:
        """Verify message and signature."""
        message_hash = hash_message(message)
        return self.verify_msg_hash(message_hash, public_key)

    def verify_msg_hash(self, message_hash: bytes, public_key: PublicKey) -> bool:
        """Verify message hash and signature."""
        return _secp256k1.verify(self.r, self.s, message_hash, public_key.to_bytes())

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

    def __getitem__(self, index: int) -> int:  # type: ignore[override]
        return self._raw_signature[index]

    def __eq__(self, other: Any) -> bool:
        if hasattr(other, "to_bytes"):
            return cast(bool, self.to_bytes() == other.to_bytes())
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
    "keccak256",
]
