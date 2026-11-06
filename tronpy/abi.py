import functools
from collections.abc import Iterable
from typing import Any, cast

from eth_abi.base import parse_type_str
from eth_abi.codec import ABICodec as ETHABICodec
from eth_abi.decoding import BaseDecoder, Fixed32ByteSizeDecoder, UnsignedIntegerDecoder
from eth_abi.encoding import BaseEncoder, Fixed32ByteSizeEncoder, UnsignedIntegerEncoder
from eth_abi.exceptions import NonEmptyPaddingBytes
from eth_abi.registry import ABIRegistry, BaseEquals
from eth_abi.registry import registry as default_registry

from tronpy.keys import is_address, to_base58check_address, to_tvm_address


class TronAddressDecoder(Fixed32ByteSizeDecoder):
    value_bit_size = 20 * 8  # type: ignore[assignment]
    is_big_endian = True  # type: ignore[assignment]
    decoder_fn = staticmethod(to_base58check_address)

    @parse_type_str("address")
    def from_type_str(cls: Any, abi_type: Any, registry: ABIRegistry) -> Any:
        return cls()

    def validate_padding_bytes(self, value: Any, padding_bytes: bytes) -> None:
        value_byte_size = self._get_value_byte_size()  # type: ignore[no-untyped-call]
        padding_size = self.data_byte_size - value_byte_size

        if (
            padding_bytes != b"\x00" * padding_size
            and padding_bytes != b"\x00" * (padding_size - 2) + b"\x00A"
            and self.strict
        ):
            raise NonEmptyPaddingBytes(f"Padding bytes were not empty: {repr(padding_bytes)}")


class TronAddressEncoder(Fixed32ByteSizeEncoder):
    value_bit_size = 20 * 8  # type: ignore[assignment]
    encode_fn = staticmethod(to_tvm_address)
    is_big_endian = True  # type: ignore[assignment]

    @classmethod
    def validate_value(cls, value: str) -> None:
        if not is_address(value):
            cls.invalidate_value(value)

    def validate(self) -> None:
        super().validate()  # type: ignore[no-untyped-call]

        if self.value_bit_size != 20 * 8:
            raise ValueError("Addresses must be 160 bits in length")

    @parse_type_str("address")
    def from_type_str(cls: Any, abi_type: Any, registry: ABIRegistry) -> Any:
        return cls()


class TrcTokenDecoder(UnsignedIntegerDecoder):
    @parse_type_str("trcToken")
    def from_type_str(cls: Any, abi_type: Any, registry: ABIRegistry) -> Any:
        return cls(value_bit_size=256)


class TrcTokenEncoder(UnsignedIntegerEncoder):
    @parse_type_str("trcToken")
    def from_type_str(cls: Any, abi_type: Any, registry: ABIRegistry) -> Any:
        return cls(value_bit_size=256)


def do_patching(registry: ABIRegistry) -> None:
    registry.unregister("address")

    registry.register(
        BaseEquals("address"),
        TronAddressEncoder,
        TronAddressDecoder,
        label="address",
    )

    registry.register(
        BaseEquals("trcToken", with_sub=False),
        TrcTokenEncoder,
        TrcTokenDecoder,
        label="trcToken",
    )

    # https://github.com/ethereum/eth-abi/pull/240
    def _get_decoder_uncached_new(self: ABIRegistry, type_str: str, strict: bool = True) -> Any:
        decoder = self._get_registration(self._decoders, type_str)
        decoder.strict = strict
        return decoder

    registry._get_decoder_uncached = _get_decoder_uncached_new.__get__(registry, registry.__class__)  # type: ignore[method-assign]
    registry.get_decoder = functools.lru_cache(maxsize=None)(registry._get_decoder_uncached)


class ABICodec(ETHABICodec):
    def encode_single(self, typ: str, arg: Any) -> bytes:
        encoder = cast(BaseEncoder, self._registry.get_encoder(typ))
        return encoder(arg)

    def decode_single(self, typ: str, data: bytes) -> Any:
        decoder = cast(BaseDecoder, self._registry.get_decoder(typ))
        stream = self.stream_class(data)  # type: ignore[no-untyped-call]
        return decoder(stream)

    def encode_abi(self, types: Iterable[str], args: Iterable[Any]) -> bytes:
        return super().encode(types, args)

    def decode_abi(self, types: Iterable[str], data: bytes, strict: bool = True) -> tuple[Any, ...]:
        return super().decode(types, data, strict)


registry = default_registry.copy()
do_patching(registry)
trx_abi = ABICodec(registry)

# alias
tron_abi = trx_abi

__all__ = ["trx_abi", "tron_abi"]
