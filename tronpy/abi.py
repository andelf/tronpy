from eth_abi import encode_single, decode_single
from eth_abi.decoding import Fixed32ByteSizeDecoder
from eth_abi.encoding import Fixed32ByteSizeEncoder
from eth_abi.registry import BaseEquals
from eth_abi.base import parse_type_str
from eth_abi.codec import ABICodec
import eth_abi
from eth_abi.registry import registry as default_registry


from tronpy.keys import to_base58check_address, is_address, to_tvm_address


class TronAddressDecoder(Fixed32ByteSizeDecoder):
    value_bit_size = 20 * 8
    is_big_endian = True
    decoder_fn = staticmethod(to_base58check_address)

    @parse_type_str("address")
    def from_type_str(cls, abi_type, registry):
        return cls()


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
        BaseEquals("address"), TronAddressEncoder, TronAddressDecoder, label="address",
    )

    registry.register(
        BaseEquals('trcToken'),
        eth_abi.encoding.UnsignedIntegerEncoder,
        eth_abi.decoding.UnsignedIntegerDecoder,
        label='trcToken',
    )


registry = default_registry.copy()
do_patching(registry)
trx_abi = ABICodec(registry)

# alias
tron_abi = trx_abi

__all__ = ["trx_abi", "tron_abi"]
