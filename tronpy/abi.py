import functools

import eth_abi
from eth_abi.base import parse_type_str
from eth_abi.codec import ABICodec as ETHABICodec
from eth_abi.decoding import Fixed32ByteSizeDecoder
from eth_abi.encoding import Fixed32ByteSizeEncoder
from eth_abi.exceptions import NonEmptyPaddingBytes
from eth_abi.registry import BaseEquals
from eth_abi.registry import registry as default_registry

from tronpy.keys import is_address, to_base58check_address, to_tvm_address


class TronAddressDecoder(Fixed32ByteSizeDecoder):
    value_bit_size = 20 * 8
    is_big_endian = True
    decoder_fn = staticmethod(to_base58check_address)

    @parse_type_str("address")
    def from_type_str(cls, abi_type, registry):
        return cls()

    def validate_padding_bytes(self, value, padding_bytes):
        value_byte_size = self._get_value_byte_size()
        padding_size = self.data_byte_size - value_byte_size

        if (
            padding_bytes != b"\x00" * padding_size
            and padding_bytes != b"\x00" * (padding_size - 2) + b"\x00A"
            and self.strict
        ):
            raise NonEmptyPaddingBytes(f"Padding bytes were not empty: {repr(padding_bytes)}")


class TronAddressEncoder(Fixed32ByteSizeEncoder):
    value_bit_size = 20 * 8
    encode_fn = staticmethod(to_tvm_address)
    is_big_endian = True

    @classmethod
    def validate_value(cls, value):
        if not is_address(value):
            cls.invalidate_value(value)

    def validate(self):
        super().validate()

        if self.value_bit_size != 20 * 8:
            raise ValueError("Addresses must be 160 bits in length")

    @parse_type_str("address")
    def from_type_str(cls, abi_type, registry):
        return cls()


def do_patching(registry):
    registry.unregister("address")

    registry.register(
        BaseEquals("address"),
        TronAddressEncoder,
        TronAddressDecoder,
        label="address",
    )

    registry.register(
        BaseEquals("trcToken"),
        eth_abi.encoding.UnsignedIntegerEncoder,
        eth_abi.decoding.UnsignedIntegerDecoder,
        label="trcToken",
    )

    def _get_decoder_uncached_new(self, type_str, strict=True):  # https://github.com/ethereum/eth-abi/pull/240
        decoder = self._get_registration(self._decoders, type_str)
        decoder.strict = strict
        return decoder

    registry._get_decoder_uncached = _get_decoder_uncached_new.__get__(registry, registry.__class__)
    registry.get_decoder = functools.lru_cache(maxsize=None)(registry._get_decoder_uncached)


class ABICodec(ETHABICodec):
    def encode_single(self, typ, arg):
        encoder = self._registry.get_encoder(typ)
        return encoder(arg)

    def decode_single(self, typ, data):
        decoder = self._registry.get_decoder(typ)
        stream = self.stream_class(data)
        return decoder(stream)

    def encode_abi(self, types, args):
        return super().encode(types, args)

    def decode_abi(self, types, data, strict=True):
        return super().decode(types, data, strict)


registry = default_registry.copy()
do_patching(registry)
trx_abi = ABICodec(registry)

# alias
tron_abi = trx_abi

__all__ = ["trx_abi", "tron_abi"]
