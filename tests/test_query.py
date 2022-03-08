import asyncio
import time

from tronpy import Tron, AsyncTron
import pytest


def test_query_account():
    client = Tron()

    # There are many TRC10 token named `BTT`
    with pytest.raises(Exception):
        btt = client.get_asset_from_name("BTT")
        print(btt)

    bals = client.get_account_asset_balances("TCrahg7N9cB1SwN21WzVMqxCptbRdvQata")
    print(bals)
    assert len(bals) > 0

    bal = client.get_account_asset_balance("TCrahg7N9cB1SwN21WzVMqxCptbRdvQata", 1002928)
    print(bal)
    assert bal > 0


@pytest.mark.asyncio
async def test_async_query_account():
    async with AsyncTron() as client:
        # There are many TRC10 token named `BTT`
        with pytest.raises(Exception):
            btt = await client.get_asset_from_name("BTT")
            print(btt)

        bals = await client.get_account_asset_balances("TCrahg7N9cB1SwN21WzVMqxCptbRdvQata")
        print(bals)
        assert len(bals) > 0

        bal = await client.get_account_asset_balance("TCrahg7N9cB1SwN21WzVMqxCptbRdvQata", 1002928)
        print(bal)
        assert bal > 0


def test_query_event_logs():
    client = Tron()
    txi = client.get_transaction_info('eb47b9779a759203899d46f2bda75c0335405f7bcba838aad8781697f216b177')
    time.sleep(1)   # due to tron official node's freq limit
    cnr = client.get_contract('TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8')
    events = list(cnr.events.Transfer.process_receipt(txi))
    assert events
    assert events[0]['event'] == 'Transfer'
    assert events[0]['address'] == 'TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8'
    assert events[0]['args'] == {
        'from': 'TMuY43m8TQ2hZ1naSiDyGujosVSMZoWLrq',
        'to': 'TXX1i3BWKBuTxUmTERCztGyxSSpRagEcjX',
        'value': 459155742
    }


@pytest.mark.asyncio
async def test_async_query_event_logs():
    async with AsyncTron() as client:
        txi = await client.get_transaction_info('eb47b9779a759203899d46f2bda75c0335405f7bcba838aad8781697f216b177')
        await asyncio.sleep(1)  # due to tron official node's freq limit
        cnr = await client.get_contract('TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8')
        events = list(cnr.events.Transfer.process_receipt(txi))
        assert events
        assert events[0]['event'] == 'Transfer'
        assert events[0]['address'] == 'TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8'
        assert events[0]['args'] == {
            'from': 'TMuY43m8TQ2hZ1naSiDyGujosVSMZoWLrq',
            'to': 'TXX1i3BWKBuTxUmTERCztGyxSSpRagEcjX',
            'value': 459155742
        }
