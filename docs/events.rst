.. _events:

Events handling
===============

Tron documentation is available at https://developers.tron.network/reference/get-events-by-transaction-id

Examples
^^^^^^^^

.. code-block:: python

   from tronpy import Tron

   client = Tron()

   # Get events by transaction id
   events = client.get_events_by_transaction_id('a7d0b8b0b8b0b8b0b8b0b8b0b8b0b8b0b8b0b8b0b8b0b8b0b8b0b8b0b8b0b8b0')

   # Get events by contract address
   events = client.get_events_by_contract_address('41b4c2a6d2b6f7c3b3e2e6e2e6e2e6e2e6e2e6e2e6')

   # Get events by block number
   events = client.get_events_by_block_number(1000000)

   # Get events of latest block
   events = client.get_events_by_block_number()
   # or
   events = client.get_events_by_block_number("latest")

