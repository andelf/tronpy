import asyncio
import inspect
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import AsyncMock, patch

import httpx2
import pytest

from tests.test_shielded import SCALING_FACTOR, SHIELDED_ADDR, T_ADDR, Z_ADDR, ZKEY, node_response
from tests.utils import check_transaction_structure
from tronpy import Contract, Tron
from tronpy.defaults import CONF_NILE
from tronpy.keys import PrivateKey
from tronpy.providers import HTTPProvider
from tronpy.tron import Transaction, TransactionBuilder, TransactionRet

FROM_ADDR = "TPX6HK2NRN4XKRX1JAhbC827bm7gMmy5w1"
FROM_PRIV_KEY = PrivateKey(bytes.fromhex("279ff36d9bf9f305af3280034bb4187c6dd299bac6b26a3c20b999c7c0d50e6e"))
TO_ADDR = "TFVfhkyJAULWQbHMgVfgbkmgeGBkHo5zru"
CNR_ADDR = "THi2qJf6XmvTJSpZHc17HgQsmJop6kb3ia"
TRANSFER_CONTRACT = {"type": "TransferContract"}
TRIGGER_CONTRACT = {"type": "TriggerSmartContract"}


@pytest.fixture
def client():
    with Tron(network="nile") as nile:
        yield nile


def test_transfer_chain(client):
    tx = client.trx.transfer(FROM_ADDR, TO_ADDR, 1).memo("test memo").fee_limit(100_000_000).build().sign(FROM_PRIV_KEY)
    check_transaction_structure(tx.to_json(), TRANSFER_CONTRACT, 100_000_000)


def test_contract_call(client):
    contract = client.get_contract(CNR_ADDR)
    assert contract.functions.name() == "Example Fixed Supply Token"
    assert contract.functions.decimals.call() == 2


def test_contract_trigger_chain(client):
    contract = client.get_contract(CNR_ADDR)
    tx = contract.functions.transfer(TO_ADDR, 1_000).with_owner(FROM_ADDR).fee_limit(5_000_000).build().sign(FROM_PRIV_KEY)
    check_transaction_structure(tx.to_json(), TRIGGER_CONTRACT, 5_000_000, expect_memo=False)


def test_from_json(client):
    tx_json = client.trx.transfer(FROM_ADDR, TO_ADDR, 1).memo("test memo").fee_limit(100_000_000).build().to_json()
    offline = Transaction.from_json(json.dumps(tx_json)).sign(FROM_PRIV_KEY)
    check_transaction_structure(offline.to_json(), TRANSFER_CONTRACT, 100_000_000)
    online = Transaction.from_json(offline.to_json(), client=client)
    check_transaction_structure(online.to_json(), TRANSFER_CONTRACT, 100_000_000)


def test_threads_share_a_client(client):
    client.get_latest_block_number()
    with ThreadPoolExecutor(4) as pool:
        numbers = list(pool.map(lambda _: client.get_latest_block_number(), range(8)))
    assert all(number > 0 for number in numbers)


def test_repeated_asyncio_run_then_sync(client):
    async def number() -> int:
        return await client.get_latest_block_number()

    assert asyncio.run(number()) > 0
    assert asyncio.run(number()) > 0
    assert client.get_latest_block_number() > 0


def test_injected_client():
    injected = httpx2.AsyncClient(timeout=httpx2.Timeout(20.0))
    with Tron(HTTPProvider(CONF_NILE, client=injected)) as custom:
        assert custom.provider.client is injected
        assert custom.get_latest_block_number() > 0
    assert injected.is_closed


def test_client_factory_across_threads_and_event_loops():
    created = []

    def factory() -> httpx2.AsyncClient:
        created.append(httpx2.AsyncClient(timeout=httpx2.Timeout(20.0)))
        return created[-1]

    async def number(client: Tron) -> int:
        return await client.get_latest_block_number()

    with Tron(HTTPProvider(CONF_NILE, client_factory=factory)) as custom:
        assert custom.get_latest_block_number() > 0
        with ThreadPoolExecutor(1) as pool:
            assert pool.submit(custom.get_latest_block_number).result() > 0
        assert asyncio.run(number(custom)) > 0
    assert len(created) == 3
    assert all(client.is_closed for client in created)


def test_contract_functions_stay_dynamic():
    contract = Contract(addr=TO_ADDR, abi=[{"type": "function", "name": "set", "inputs": [], "outputs": []}])
    assert dir(contract.functions) == ["set"]
    assert str(contract.functions.set) == "function set()"
    assert [str(function) for function in contract.functions] == ["function set()"]
    assert not hasattr(contract.functions, "missing")


def test_shielded_async_properties_and_methods():
    with patch.object(HTTPProvider, "make_request", AsyncMock(side_effect=node_response)):
        wrapper = Tron(network="nile").get_contract_as_shielded_trc20(SHIELDED_ADDR)
        assert wrapper.scale_factor == SCALING_FACTOR
        assert isinstance(wrapper.trc20, Contract)
        assert isinstance(wrapper.mint(T_ADDR, Z_ADDR, 2 * SCALING_FACTOR), TransactionBuilder)
        assert wrapper.is_note_spent(ZKEY, {"note": {}}) is False


def test_asyncio_run_on_a_call_raises_after_it_ran():
    with patch.object(HTTPProvider, "make_request", AsyncMock(return_value={"result": True, "txid": "00" * 32})) as node:
        transaction = Transaction({"expiration": 0}, client=Tron(network="nile"), txid="00" * 32)
        with pytest.raises(ValueError if sys.version_info < (3, 14) else TypeError, match="coroutine"):
            asyncio.run(transaction.broadcast())
    node.assert_awaited_once()


def test_calls_inside_a_running_loop_return_a_coroutine():
    async def main() -> None:
        with patch.object(HTTPProvider, "make_request", AsyncMock(return_value={"result": True, "txid": "00" * 32})):
            transaction = Transaction({"expiration": 0}, client=Tron(network="nile"), txid="00" * 32)
            result = transaction.broadcast()
            assert inspect.iscoroutine(result)
            assert isinstance(await result, TransactionRet)

    asyncio.run(main())
