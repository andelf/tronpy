Keys and Addresses
==================

There are two types of address format, "base58check" and "hex str". The `base58check` variant is more user-friendly.

TronPy accepts both type of address. The `Base58check` type is preferred.

Key API reference
-----------------

.. autofunction:: tronpy.keys.to_base58check_address

.. autoclass:: tronpy.keys.PrivateKey
   :members:

   .. automethod:: fromhex(hex_str)
   .. automethod:: hex()

.. autoclass:: tronpy.keys.PublicKey
   :members:

   .. automethod:: fromhex(hex_str)
   .. automethod:: hex()

.. autoclass:: tronpy.keys.Signature
   :members: