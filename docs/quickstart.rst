.. _quickstart:

Quickstart
==========

Installation
------------

TronPy can be installed using pip as follows:

.. code-block:: console

   > pip3 install tronpy

.. note::
   Only Python 3.6+ is supported.

Using TronPy
------------

This library depends on a connection to an TRON node. We call these connections `Providers`. Currently,
only HTTP Provider is available.

There are preset networks along with client, use ``network=`` to choose from the mainnet or testnets.

The mainnet
^^^^^^^^^^^

.. code-block:: python

   from tronpy import Tron

   client = Tron()  # The default provicder, mainnet

Testnets
^^^^^^^^

.. code-block:: python

   from tronpy import Tron

   client = Tron(network="nile")  # The Nile Testnet is preset
   # or "shasta", "tronex"

Private network
^^^^^^^^^^^^^^^

.. code-block:: python

   from tronpy import Tron
   from tronpy.providers import HTTPProvider

   client = Tron(HTTPProvider("http://127.0.0.1:8090"))  # Use private network as HTTP API endpoint

With custom default fee limit
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The default fee limit is ``5_000_000`` for contract deploy or trigger, ``0`` otherwise.

.. code-block: python

  # set fee_limit 10 TRX
  client = Tron(network='nile', conf={'fee_limit': 10_000_000})

Getting Blockchain Info
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   >>> client.get_block()
   {'blockID': '000000000064ac1f04aa38427cb78fb537c6b13115f2e6ed225625990af01a3f',
    'block_header': {'raw_data': {'number': 6597663,
                                'parentHash': '000000000064ac1e8be0ae18b26a066e04d2895948d1a318ded6add9f0712641',
                                'timestamp': 1592503713000,
                                'txTrieRoot': '0000000000000000000000000000000000000000000000000000000000000000',
                                'version': 16,
                                'witness_address': '41e98ec1e5d55585f19cd9759d494af777d7041e0e'},
                    'witness_signature': '7aa9ece51dc0e82b683570b2c9b792a5b1e298d52c6adb109cb3abb487a87948552007bd7baab6c8c539e9d105e324e6cb40da650e87595b4da08329b405083101'}}
