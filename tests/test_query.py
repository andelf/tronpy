from tronpy import Tron, AsyncTron
from tronpy.keys import PrivateKey
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
