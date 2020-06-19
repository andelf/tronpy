Shielded TRC20
==============

Shielded TRC20 is only available on Nile Testnet for now.

A :class:`~tronpy.contract.ShieldedTRC20` wrapper can be acquired by
:meth:`~tronpy.Tron.get_contract_as_shielded_trc20` call.

A full set of shielded address keys can be acquired by :meth:`~tronpy.Tron.generate_zkey` call.

Generate shielded address
-------------------------

.. code-block:: python

  >>> from tronpy import Tron
  >>> client = Tron(network='nile')

  >>> client.generate_zkey()
  {'ak': 'd06c283d7c9a189710c323058a27d9c96e4b21fbd7a0fbabecb5d605d1190fe0',
  'ask': 'e6268e981533004ea6ce05dcb68d74258962142e8e10246d22f07f2ef08d8b0c',
  'd': '1c1348babd32e8b1fb556b',
  'ivk': '4f8757ec009325e3a4ead1988986cc6ad078951caa6e948534d4a3ca77e64903',
  'nk': '82e3f4028a019f8e2510e95f2109e9ce0401ceb37c3f8288b84a9c796c9f7913',
  'nsk': '298b8ef945c1aa04a81fe04c5cd44ca674c6393053078bc6b3200414544ac109',
  'ovk': 'd82520ba6aedd623ff831ca89bba9cc9d78a44eabf4d5099922386a7e5ee4dc1',
  'payment_address': 'ztron1rsf53w4axt5tr764dvh035tsgfmwjga66v3g9dulazq2jzxnk63t2dupvl7ufca0fnjdj98xqqg',
  'pkD': '2ef8d1704276e923bad32282b79fe880a908d3b6a2b5378167fdc4e3af4ce4d9',
  'sk': '.........................omitted.......................'}

Transfer shielded TRC20 tokens
------------------------------

There are 3 types of shielded transfer:

* mint: from T-address to z-address
* transfer: from z-address to z-address
* burn: from z-address to T-address

To use the :class:`~tronpy.contract.ShieldedTRC20` wrapper:

.. code-block:: python

  client = Tron(network='nile')
  shielded_trc20 = client.get_contract_as_shielded_trc20('TGbsfpmaPuSqQyEgieQTd5aZN9XvEMga7e')

  taddr = 'TJRabPrwbZy45sbavfcjinPJC18kjpRTv8'
  priv_key = PrivateKey(bytes.fromhex("................omitted.............................."))

  # check allowance
  print('Allowance:', shielded_trc20.trc20.functions.allowance(taddr, shielded_trc20.shielded.contract_address))

  # or approve transferFrom
  # shielded_trc20.trc20.functions.approve(taddr, 1000_000_000).with_owner(taddr).build().sign(priv_key).broadcast().wait()

  txn = (
      shielded_trc20.mint(taddr, zkey['payment_address'], 1_100, 'The Memo').fee_limit(5_000_000).build().sign(priv_key)
  )
  print(txn.broadcast().wait())


Scan notes
----------

.. code-block:: python

  notes = shielded_trc20.scan_incoming_notes(zkey, 6587490)

  # or
  notes = shielded_trc20.scan_incoming_notes(zkey, client.get_latest_block_number() - 100)


API reference
-------------

.. autoclass:: tronpy.contract.ShieldedTRC20()
   :members:
