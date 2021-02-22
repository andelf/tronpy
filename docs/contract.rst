Smart Contract
==============

Smart contract is the key feature of TRON network. Creating and interacting with smart contract are made easy by TronPy.

Calling smart contract
----------------------

There are two types of smart contract call, `const call` and `trigger call`. For a `const call`, the contract method
must be marked `pure` or `view`. And the calling result will be returned immediately.

While the `trigger call` is just a type of system contract call, you sign the calling transaction, and broadcast it.
The calling result can be fetched and parsed through the API.

Const call
^^^^^^^^^^

Const call is wrapped as a function object. The result is parsed according to ABI.

Take TRC20 as an example, the `balance query` is a very common task:

.. code-block:: python

  from tronpy import Tron

  client = Tron(network='nile')

  cntr = client.get_contract("THi2qJf6XmvTJSpZHc17HgQsmJop6kb3ia")

  print(dir(cntr.functions))  # prints list of contract functions

  for f in cntr.functions:
      print(f)  # prints function signature(i.e. type info)

  # function allowance(address _owner, address _spender) view returns (uint256 remaining)
  # function approve(address _spender, uint256 _amount) returns (bool success)
  # function balanceOf(address _owner) view returns (uint256 balance)
  # function decimals() view returns (uint8 )
  # function name() view returns (string )
  # function owner() view returns (address )
  # function symbol() view returns (string )
  # function totalSupply() view returns (uint256 theTotalSupply)
  # function transfer(address _to, uint256 _amount) returns (bool success)
  # function transferFrom(address _from, address _to, uint256 _amount) returns (bool success)

  print('Symbol:', cntr.functions.symbol())  # The symbol string of the contract
  # Symbol: RMB

  precision = cntr.functions.decimals()
  print('Balance:', cntr.functions.balanceOf('TJRabPrwbZy45sbavfcjinPJC18kjpRTv8') / 10 ** precision)
  # Balance: 100000.0

Trigger call
^^^^^^^^^^^^

Trigger call requires sign and broadcast.

.. code-block:: python

  >>> from tronpy import Tron                                                                                                                                                                  from tronpy.keys import PrivateKey
  >>> from tronpy.keys import PrivateKey

  >>> client = Tron(network='nile')
  >>> contract = client.get_contract('THi2qJf6XmvTJSpZHc17HgQsmJop6kb3ia')

  >>> print(contract.functions.transfer)
  function transfer(address _to, uint256 _amount) returns (bool success)

  >>> txn = (
  ...         contract.functions.transfer('TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA', 1_000)
  ...         .with_owner('TGQgfK497YXmjdgvun9Bg5Zu3xE15v17cu')  # address of the private key
  ...         .fee_limit(5_000_000)
  ...         .build()
  ...         .sign(priv_key)
  ... )
  >>> txn.broadcast()  # or txn.broadcast()
  {'result': True, 'txid': '63609d84524b754a97c111eec152700f273979bb00dad993d8dcce5848b4dd9a'}
  >>> _.wait()
  {'id': '63609d84524b754a97c111eec152700f273979bb00dad993d8dcce5848b4dd9a',
   'blockNumber': 6609475, 'blockTimeStamp': 1592539509000,
   'contractResult': ['0000000000000000000000000000000000000000000000000000000000000001'],
   'contract_address': 'THi2qJf6XmvTJSpZHc17HgQsmJop6kb3ia',
   'receipt': {'energy_usage': 13062, 'energy_usage_total': 13062, 'net_usage': 344, 'result': 'SUCCESS'},
   'log': [{'address': 'THi2qJf6XmvTJSpZHc17HgQsmJop6kb3ia',
            'topics': ['ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
                       '00000000000000000000000046a23e25df9a0f6c18729dda9ad1af3b6a131160',
                       '000000000000000000000000d8dd39e2dea27a40001884901735e3940829bb44'],
            'data': '00000000000000000000000000000000000000000000000000000000000003e8'}]}

  # trigger output can be parsed manually
  >>> contract.functions.transfer.parse_output(_['contractResult'][0])
  True
  # or use `.result()` to parse it automatically
  >>> txn.broadcast().result()
  True

Trigger call with transfer
^^^^^^^^^^^^^^^^^^^^^^^^^^

Use :meth:`~tronpy.contract.ContractMethod.with_transfer` or :meth:`~tronpy.contract.ContractMethod.with_asset_transfer`.

.. code-block:: python

  >>> txn = (
  ...         contract.functions.transfer.with_transfer(100_000_000)
  ...         .call('TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA', 1_000)
  ...         .with_owner('TGQgfK497YXmjdgvun9Bg5Zu3xE15v17cu')  # address of the private key
  ...         .fee_limit(5_000_000)
  ...         .build()
  ...         .sign(priv_key)
  ... )


Creating smart contract
-----------------------

When you've compiled your contract code, you can deploy it on chain.

.. code-block:: python

  from tronpy import Tron, Contract
  from tronpy.keys import PrivateKey

  client = Tron(network='nile')
  priv_key = PrivateKey(bytes.fromhex("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"))

  bytecode = "608060405234801561001057600080fd5b5060c78061001f6000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea2646970667358221220c8daade51f673e96205b4a991ab6b94af82edea0f4b57be087ab123f03fc40f264736f6c63430006000033"
  abi = [
      {
          "inputs": [],
          "name": "get",
          "outputs": [{"internalType": "uint256", "name": "retVal", "type": "uint256"}],
          "stateMutability": "view",
          "type": "function",
      }
  ]

  cntr = Contract(name="SimpleStore", bytecode=bytecode, abi=abi)

  txn = (
      client.trx.deploy_contract('TGQgfK497YXmjdgvun9Bg5Zu3xE15v17cu', cntr)
      .fee_limit(5_000_000)
      .build()
      .sign(priv_key)
  )
  print(txn)
  result = txn.broadcast().wait()
  print(result)
  print('Created:', result['contract_address'])

  created_cntr = client.get_contract(result['contract_address'])

.. note::

   The constructor's parameters are provided via `bytecode`.

.. code-block:: python

  cntr = Contract(name="SimpleStore", bytecode=bytecode, abi=abi)
  parameter = cntr.constructor.encode_parameter("TRh5N2iAmjyeJbbCXsDuo7PNZvyjVWtL2e", 18)
  cntr.bytecode = bytecode + parameter

Default Fee Limit
-----------------

The default fee limit is ``5_000_000`` for contract deploy or trigger, ``0`` otherwise.

Fee limit is set by ``.fee_limit()`` method of transaction.

It also can be set via `conf` object:

.. code-block:: python

  client = Tron(network='nile', conf={'fee_limit': 10_000_000})

Contract with Un-published ABI
------------------------------

You can set JSON ABI via ``cntr.abi = [...]``.

.. code-block:: python

  import json

  from tronpy import Tron
  from tronpy import keys


  dzi_trade = 'TS..........(omitted).............j'
  from_addr = 'TV..........(omitted).............a'
  priv_key = keys.PrivateKey(bytes.fromhex("975a...............(omitted)..............8d97b"))
  abi = '''
  [{"constant":false,
    "inputs":[{"name":"min_tokens","type":"uint256"},{"name":"deadline","type":"uint256"}],
    "name":"trxToTokenSwapInput",
    "outputs":[{"name":"","type":"uint256"}],
    "payable":true,
    "stateMutability":"payable",
    "type":"Function"}]
  '''


  client = Tron(network='nile')

  cntr = client.get_contract(dzi_trade)
  cntr.abi = json.loads(abi)  # load ABI, while contract on chain has no ABI set.

  # call contract functions with TRX transfer
  txn = (
      cntr.functions.trxToTokenSwapInput.with_transfer(1_000_000_000)(1_000_000_000_000, 5)
      .with_owner(from_addr)
      .fee_limit(1_000_000_000)
      .build()
      .sign(priv_key)
  )
  print("txn =>", txn)
  print("broadcast and result =>", txn.broadcast().wait())


API reference
-------------

.. autoclass:: tronpy.contract.Contract
   :members:

.. autoclass:: tronpy.contract.ContractFunctions()
   :members:

   .. automethod:: __getattr__(method: str) -> tronpy.contract.ContractMethod

.. autoclass:: tronpy.contract.ContractMethod()
   :members:

   .. automethod:: __call__(*args, **kwargs)
