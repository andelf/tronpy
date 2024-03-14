The Hierarchical Deterministic (HD) Wallet API
==============================================

TronPy HD wallet API can be used by installing `mnemonic` as follows:

.. code-block:: console

   > pip3 install tronpy[mnemonic]

Calling HD Wallet APIs
----------------------

The :class:`~tronpy.Tron` wraps many query APIs and utility functions. You use it using either ``Tron`` or ``AsyncTron`` classes

.. code-block:: python

  >>> from tronpy import Tron
  >>> client = Tron()
  >>> client.generate_address_with_mnemonic()
  ({'base58check_address': 'TU7r98aQ3XTHuM9NLwnyVmdCH7gAZDYqxt',
  'hex_address': '41c71498123f6de4698410712e5f5c96ae42978776',
  'private_key': '.................omitted.....................',
  'public_key': '..................omitted.....................'},
  'abandon length scan lesson mammal elite noodle ...omitted...')
  >>> client.generate_address_with_mnemonic(
  ...   passphrase='superSecret', # Like a password for the generated mnemonic code
  ...   num_words=12 # Length of the mnemonic code to generate. Default is 12 words but can be (12, 15, 18, 21, 24)
  ...   )
  ({'base58check_address': 'TU7r98aQ3XTHuM9NLwnyVmdCH7gAZDYqxt',
  'hex_address': '41c71498123f6de4698410712e5f5c96ae42978776',
  'private_key': '.................omitted.....................',
  'public_key': '..................omitted.....................'},
  'abandon length scan lesson mammal elite noodle ...omitted...')
  >>> client.generate_address_from_mnemonic('abandon length scan lesson mammal elite noodle ...omitted...')
  {'base58check_address': 'TU7r98aQ3XTHuM9NLwnyVmdCH7gAZDYqxt',
  'hex_address': '41c71498123f6de4698410712e5f5c96ae42978776',
  'private_key': '.................omitted.....................',
  'public_key': '..................omitted.....................'}
  >>> client.generate_address_from_mnemonic('abandon length scan lesson mammal elite noodle ...omitted...', passphrase='super secret')
  {'base58check_address': 'TU7r98aQ3XTHuM9NLwnyVmdCH7gAZDYqxt',
  'hex_address': '41c71498123f6de4698410712e5f5c96ae42978776',
  'private_key': '.................omitted.....................',
  'public_key': '..................omitted.....................'}
  >>> client.generate_address_from_mnemonic(
  ...   'abandon length scan lesson mammal elite noodle ...omitted...',
  ...   passphrase='superSecret'
  ...   account_path="m/44'/195'/0'/0/0" # "m/(purpose: constant as 44)'/(coin_type: Tron is 195)'/(account: increments from 0)'/(change: default is 0)/(address_index: increments from 0)"; For more details check `BIP44 <https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#user-content-Path_levels>`
  ...   )
  {'base58check_address': 'TU7r98aQ3XTHuM9NLwnyVmdCH7gAZDYqxt',
  'hex_address': '41c71498123f6de4698410712e5f5c96ae42978776',
  'private_key': '.................omitted.....................',
  'public_key': '..................omitted.....................'}

Using Async API
---------------

The async client is ``AsyncTron``. It uses almost the same API as the synchronous client ``Tron``.

.. code-block:: python

  import asyncio

  from tronpy import AsyncTron

  async def create_hd_wallet(passphrase, num_of_words):
      async with AsyncTron(network='nile') as client:
          print(client)

          first_index_wallet_details, mnemonic_code = client.generate_address_with_mnemonic(passphrase=passphrase, num_words=num_of_words)

          print(mnemonic_code)
          # > 'abandon length scan lesson mammal elite noodle ...omitted...'
          print(first_index_wallet_details)
          # > {'base58check_address': 'TJzXt1sZautjqXnpjQT4xSCBHNSYgBkDr3', 'hex_address': '41c71498123f6de4698410712e5f5c96ae42978776', 'private_key': '.................omitted.....................', 'public_key': '..................omitted.....................'}
          return passphrase, mnemonic_code, first_index_wallet_details['base58check_address']

  async def derive_hd_wallet(mnemonic_str, passphrase="", account_number=0, account_index=0):
      async with AsyncTron(network='nile') as client:
          print(client)

          wallet_details = client.generate_address_from_mnemonic(mnemonic=mnemonic_str, passphrase=passphrase, account_path=f"m/44'/195'/{account_number}'/0/{account_index}")

          print(wallet_details)
          # > {'base58check_address': 'TJzXt1sZautjqXnpjQT4xSCBHNSYgBkDr3', 'hex_address': '41c71498123f6de4698410712e5f5c96ae42978776', 'private_key': '.................omitted.....................', 'public_key': '..................omitted.....................'}
          return wallet_details

  async def main():
      passphrase, mnemonic_code, wallet_address = await create_hd_wallet('superSecret', 24)

      wallet_details = await derive_hd_wallet(mnemonic_code, passphrase, account_number=0, account_index=0)
      print(wallet_address == wallet_details['base58check_address'])
      # > True

      wallet_details = await derive_hd_wallet(mnemonic_code, passphrase, account_number=0, account_index=1)
      print(wallet_address == wallet_details['base58check_address'])
      # > False

  if __name__ == '__main__':
      asyncio.run(main())
