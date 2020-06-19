Sending Transaction
===================

A Transaction in TRON is a system contract call, including TRX transfer, TRC10 transfer, contract call, create contract,
vote witness, create new TRC10 token, and so on. The system contract call will be saved on the blockchain(in a block
as a element in transactions list).

The routine for sending
-----------------------

A normal routine for sending a transaction is:

.. code-block::

   Create -> Sign -> Broadcast -> (wait) -> Lookup and get receipt

TronPy chooses the `method chaining <https://en.wikipedia.org/wiki/Method_chaining>`_ approach to create,
sign, and broadcast any transaction. All type of transactions can be created via :class:`Tron.trx <tronpy.tron.Trx>` object.

.. code-block:: python

  from tronpy import Tron
  from tronpy.keys import PrivateKey

  client = Tron(network='nile')
  priv_key = PrivateKey(bytes.fromhex("8888888888888888888888888888888888888888888888888888888888888888"))

  txn = (
      client.trx.transfer("TJzXt1sZautjqXnpjQT4xSCBHNSYgBkDr3", "TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA", 1_000)
      .memo("test memo")
      .build()
      .sign(priv_key)
  )
  print(txn.txid)
  print(txn.broadcast().wait())

In TronPy, the routine is:

0. Create a :class:`TRON API client <tronpy.Tron>`
1. Create a :class:`~tronpy.tron.TransactionBuilder` via :class:`client.trx.foo <tronpy.tron.Trx>` functions
2. Optionally set :meth:`~tronpy.tron.TransactionBuilder.fee_limit`, :meth:`~tronpy.tron.TransactionBuilder.memo`,
   or :meth:`~tronpy.tron.TransactionBuilder.permission_id`
3. Call ``builder.``:meth:`~tronpy.tron.TransactionBuilder.build`, create a :class:`~tronpy.tron.Transaction` object
4. Call ``transaction.``:meth:`~tronpy.tron.Transaction.sign`, to sign the transaction with a
   :class:`private key <tronpy.keys.PrivateKey>`. Multiple calling of `sign` means `multi-sign`
5. Call ``transaction.``:meth:`~tronpy.tron.Transaction.broadcast`, to broadcast the transaction object
6. Optionally call ``ret.``:meth:`~tronpy.tron.TransactionRet.wait`, to wait and query the transaction receipt

The above steps are made easy through following APIs.

API reference
-------------

.. autoclass:: tronpy.tron.Trx()
   :members:

.. autoclass:: tronpy.tron.TransactionBuilder()
   :members:

.. autoclass:: tronpy.tron.Transaction()
   :members:

.. autoclass:: tronpy.tron.TransactionRet()
   :members:
