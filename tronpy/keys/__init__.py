import ecdsa  # type: ignore
from Crypto.Hash import keccak
import hashlib
import base58
from collections.abc import ByteString, Hashable
import random
from typing import Any, Union

from tronpy.exceptions import BadKey, BadSignature, BadAddress


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
            except ValueError:
                raise BadAddress("bad base58check format")
            return raw_addr
        elif len(raw_addr) == 42:
            if raw_addr.startswith("0x"):  # eth address format
                return base58.b58encode_check(b"\x41" + bytes.fromhex(raw_addr[2:])).decode()
            else:
                return base58.b58encode_check(bytes.fromhex(raw_addr)).decode()
        elif raw_addr.startswith("0x") and len(raw_addr) == 44:
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


class BaseKey(ByteString, Hashable):
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
        elif isinstance(other, (bytes, bytearray)):
            return self.to_bytes() == other
        else:
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
        try:
            assert isinstance(public_key_bytes, (bytes,))
            assert len(public_key_bytes) == 64
        except AssertionError:
            raise BadKey

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
        try:
            assert isinstance(private_key_bytes, (bytes,))
            assert len(private_key_bytes) == 32
            assert (
                0
                < int.from_bytes(private_key_bytes, "big")
                < 115792089237316195423570985008687907852837564279074904382605163141518161494337
            )
        except AssertionError:
            raise BadKey

        self._raw_key = private_key_bytes

        priv_key = ecdsa.SigningKey.from_string(self._raw_key, curve=ecdsa.SECP256k1)
        self.public_key = PublicKey(priv_key.get_verifying_key().to_string())

        super().__init__()

    def sign_msg(self, message: bytes) -> "Signature":
        """Sign a raw message."""
        sk = ecdsa.SigningKey.from_string(self._raw_key, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
        signature = sk.sign_deterministic(message)

        # recover address to get rec_id
        vks = ecdsa.VerifyingKey.from_public_key_recovery(
            signature, message, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256
        )
        for v, pk in enumerate(vks):
            if pk.to_string() == self.public_key:
                break

        signature += bytes([v])
        return Signature(signature)

    def sign_msg_hash(self, message_hash: bytes) -> "Signature":
        """Sign a message hash(sha256)."""
        sk = ecdsa.SigningKey.from_string(self._raw_key, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
        signature = sk.sign_digest_deterministic(message_hash)

        # recover address to get rec_id
        vks = ecdsa.VerifyingKey.from_public_key_recovery_with_digest(
            signature, message_hash, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256
        )
        for v, pk in enumerate(vks):
            if pk.to_string() == self.public_key:
                break

        signature += bytes([v])
        return Signature(signature)

    @classmethod
    def random(cls) -> "PrivateKey":
        """Generate a random private key."""
        return cls(bytes([random.randint(0, 255) for _ in range(32)]))

    @classmethod
    def from_passphrase(cls, passphrase: bytes) -> "PrivateKey":
        """Get a private key from sha256 of a passphrase."""
        return cls(sha256(passphrase))


class Signature(ByteString):
    """The signature object."""

    _raw_signature = None

    def __init__(self, signature_bytes: bytes):
        try:
            assert isinstance(signature_bytes, (bytes,))
            assert len(signature_bytes) == 65
            assert signature_bytes[-1] in [0, 1]
        except AssertionError:
            raise BadSignature

        self._raw_signature = signature_bytes

        super().__init__()

    def recover_public_key_from_msg(self, message: bytes) -> PublicKey:
        """Recover public key(address) from message and signature."""
        vks = ecdsa.VerifyingKey.from_public_key_recovery(
            self._raw_signature[:64], message, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256
        )
        return PublicKey(vks[self.v].to_string())

    def recover_public_key_from_msg_hash(self, message_hash: bytes) -> PublicKey:
        """Recover public key(address) from message hash and signature."""
        vks = ecdsa.VerifyingKey.from_public_key_recovery_with_digest(
            self._raw_signature[:64], message_hash, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256
        )
        return PublicKey(vks[self.v].to_string())

    def verify_msg(self, message: bytes, public_key: PublicKey) -> bool:
        """Verify message and signature."""
        vk = ecdsa.VerifyingKey.from_string(public_key.to_bytes(), curve=ecdsa.SECP256k1)
        return vk.verify(self._raw_signature[:64], message, hashfunc=hashlib.sha256)

    def verify_msg_hash(self, message_hash: bytes, public_key: PublicKey) -> bool:
        """Verify message hash and signature."""
        vk = ecdsa.VerifyingKey.from_string(public_key.to_bytes(), curve=ecdsa.SECP256k1)
        return vk.verify_digest(self._raw_signature[:64], message_hash)

    @property
    def v(self) -> int:
        return self._raw_signature[64]

    def hex(self) -> str:
        """
        Return signature as a hex str.

        :returns: A hex str.
        """
        return self._raw_signature.hex()

    @classmethod
    def fromhex(cls, hex_str: str) -> 'Signature':
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
        elif isinstance(other, (bytes, bytearray)):
            return self.to_bytes() == other
        else:
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
]
