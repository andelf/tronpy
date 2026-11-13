import pytest

from tronpy import Tron


@pytest.mark.asyncio
async def test_query_account():
    async with Tron(network="nile") as client:
        # There are many TRC10 token named `BTT`
        with pytest.raises(ValueError):
            await client.get_asset_from_name("BTT")

        bals = await client.get_account_asset_balances("TUyk7E8VqitrD1iFLVMcYg9jbjtD7sMhvF")
        assert len(bals) > 0

        bal = await client.get_account_asset_balance("TUyk7E8VqitrD1iFLVMcYg9jbjtD7sMhvF", 1000016)
        assert bal > 0


@pytest.mark.asyncio
async def test_query_event_logs():
    async with Tron(network="nile") as client:
        txi = await client.get_transaction_info("927c27150f70f0d5762486e3edd626775fe1edab1069ff2182d133807c37f705")
        cnr = await client.get_contract("TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf")
        events = list(cnr.events.Transfer.process_receipt(txi))
        assert events
        assert events[0]["event"] == "Transfer"
        assert events[0]["address"] == "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf"
        assert events[0]["args"] == {
            "from": "TC4JGN4xJUcZgBoLj9fEe8bh5kqAL47Pcx",
            "to": "TAmACnEmTUT7a8topHfTNG1WKXXynQo2yX",
            "value": 1000000,
        }
