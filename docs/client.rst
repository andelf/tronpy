HTTP API Client
===============

TronPy uses TRON HTTP API to communicate with TRON nodes. The main client class is :class:`~tronpy.Tron`.

Creating client
---------------

Refer :ref:`quickstart` for creating clients.

Calling query APIs
------------------

The :class:`~tronpy.Tron` wraps many query APIs and utility functions. You can query the chain using a instance.

.. code-block:: python

  >>> from tronpy import Tron
  >>> client = Tron()
  >>> client.get_latest_block_number()
  20746184
  >>> client.get_latest_block_id()
  '00000000013c8fc9a74d2ef9111d2216b9bec4b0fbf44e2e77711dde0e535f8e'
  >>> client.get_account_balance('TTzPiwbBedv7E8p4FkyPyeqq4RVoqRL3TW')
  Decimal('286820.078511')
  >>> client.get_account_asset_balance('TCrahg7N9cB1SwN21WzVMqxCptbRdvQata', 1002928)
  989937719235000000


  >>> client.generate_address()
  {'base58check_address': 'TU7r98aQ3XTHuM9NLwnyVmdCH7gAZDYqxt',
   'hex_address': '41c71498123f6de4698410712e5f5c96ae42978776',
   'private_key': '.................omitted.....................',
   'public_key': '..................omitted.....................'}

API reference
-------------

.. autoclass:: tronpy.Tron
   :members:

.. autoclass:: tronpy.providers.HTTPProvider
   :members:
