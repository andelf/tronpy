

import json
import os
import time

from tronpy import Tron
from tronpy import keys

__dir__ = os.path.dirname(__file__)

dzi_trade = 'TSMssi9ojNkzj5fT5bAjzuGjrLmsKau8Xj'
from_addr = 'TVrSWkL6a9xvtxRKq5RHg2HjUpGdPN3wBa'
priv_key = keys.PrivateKey.fromhex("975a98.....(omitted)..........86b98d97b")


def timestamp():
    return int(time.time())

swap_abi = []
with  open(os.path.join(__dir__, "JustSwapExchange.abi")) as fp:
    swap_abi = json.load(fp)


client = Tron(network='nile')

cntr = client.get_contract(dzi_trade)
cntr.abi = swap_abi

for f in cntr.functions:
    print(f)

# call contract functions with TRX transfer
txn = (
    cntr.functions.trxToTokenSwapInput.with_transfer(1_000_000_000)(1_000_000_000, timestamp() + 120)
    .with_owner(from_addr)
    .fee_limit(1_000_000_000)
    .build()
    .sign(priv_key)
)
print("txn =>", txn)
# print("broadcast and result =>", txn.broadcast().wait())

# NOTE: before calling tokenToTrxSwapInput, you MUST add TRC20 allowance to the swap contract.
