ABI encode and decode
=====================

TRON's ABI has a little difference from ETH's ABI.

- Different Address format
- Add a new type ``trcToken`` to denote TRC10 token ID.

TronPy provides ABI encoding and decoding methods via the ``tronpy.abi`` module.


.. code-block:: python

   >>> from tronpy.abi import trx_abi

   # function arguments as a tuple
   >>> raw = trx_abi.encode_single("(address,uint256)", ["TLfuw4tRywtxCusvTudbjf7PbcXjfe7qrw", 100_000_000])
   >>> print(raw.hex())
   '0000000000000000000000007564105e977516c53be337314c7e53838967bdac
    0000000000000000000000000000000000000000000000000000000005f5e100'

   # function arguments as list
   >>> raw = trx_abi.encode_abi(['address', 'uint256'], ["TLfuw4tRywtxCusvTudbjf7PbcXjfe7qrw", 100_000_000])

   >>> trx_abi.decode_abi(['address', 'uint256'],
   ...   bytes.fromhex('0000000000000000000000007564105e977516c53be337314c7e53838967bdac' + \
   ...       '0000000000000000000000000000000000000000000000000000000005f5e100'))
   ('TLfuw4tRywtxCusvTudbjf7PbcXjfe7qrw', 100000000)

Key API reference
-----------------

.. autofunction:: tronpy.abi.trx_abi.encode_abi

.. autofunction:: tronpy.abi.trx_abi.encode_single

.. autofunction:: tronpy.abi.trx_abi.decode_abi

.. autofunction:: tronpy.abi.trx_abi.decode_single
