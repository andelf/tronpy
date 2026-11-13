import asyncio
from concurrent.futures import ThreadPoolExecutor

import httpx2
import pytest

from tronpy import Tron
from tronpy.providers import HTTPProvider

NODE = "http://node.test"


def mock_client() -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        transport=httpx2.MockTransport(lambda request: httpx2.Response(200, json={"url": str(request.url)}))
    )


@pytest.mark.asyncio
async def test_injected_client_is_used_and_closed_with_the_client():
    injected = mock_client()
    provider = HTTPProvider(NODE, client=injected)
    assert provider.client is injected
    assert await provider.make_request("wallet/getnodeinfo") == {"url": f"{NODE}/wallet/getnodeinfo"}

    await Tron(provider).close()
    assert injected.is_closed


def test_injected_client_is_only_used_on_its_event_loop():
    injected = mock_client()
    provider = HTTPProvider(NODE, timeout=3.0, client=injected)
    assert provider.client is injected

    async def client_of_other_loop() -> httpx2.AsyncClient:
        return provider.client

    other = asyncio.run(client_of_other_loop())
    assert other is not injected
    assert other.timeout == httpx2.Timeout(3.0)
    assert provider.client is not injected
    provider.close()
    assert injected.is_closed


def test_each_event_loop_gets_its_own_client():
    provider = HTTPProvider(NODE)

    async def current_client() -> httpx2.AsyncClient:
        return provider.client

    first = asyncio.run(current_client())
    second = asyncio.run(current_client())
    assert second is not first
    assert first.is_closed
    with ThreadPoolExecutor(1) as pool:
        in_thread = pool.submit(lambda: provider.client).result()
    assert in_thread is not provider.client
    provider.close()
    assert in_thread.is_closed


@pytest.mark.asyncio
async def test_close_closes_clients_of_all_event_loops():
    provider = HTTPProvider(NODE)
    with ThreadPoolExecutor(1) as pool:
        in_thread = await asyncio.get_running_loop().run_in_executor(pool, lambda: provider.client)
    current = provider.client
    await provider.close()
    assert in_thread.is_closed
    assert current.is_closed


@pytest.mark.asyncio
async def test_async_with_closes_the_client():
    client = Tron(HTTPProvider(NODE))
    async with client:
        http_client = client.provider.client
    assert http_client.is_closed


def test_reuse_after_close_gets_a_new_client():
    provider = HTTPProvider(NODE)
    first = provider.client
    provider.close()
    assert provider.client is not first
    assert not provider.client.is_closed
    provider.close()


def test_client_factory_is_used_on_every_event_loop():
    created = []

    def factory() -> httpx2.AsyncClient:
        created.append(mock_client())
        return created[-1]

    provider = HTTPProvider(NODE, client_factory=factory)
    assert created == []

    async def request() -> dict:
        return await provider.make_request("wallet/getnodeinfo")

    expected = {"url": f"{NODE}/wallet/getnodeinfo"}
    assert asyncio.run(request()) == expected
    assert asyncio.run(request()) == expected
    assert provider.make_request("wallet/getnodeinfo") == expected
    assert provider.make_request("wallet/getnodeinfo") == expected
    with ThreadPoolExecutor(1) as pool:
        assert pool.submit(provider.make_request, "wallet/getnodeinfo").result() == expected
    assert len(created) == 4

    provider.close()
    assert all(client.is_closed for client in created)
    reused = provider.client
    assert len(created) == 5
    assert reused is created[-1]
    provider.close()


class CustomProvider(HTTPProvider):
    async def make_request(self, method, params=None):
        return {"block": "Num:7,ID:00"}


def test_custom_provider_from_sync_code():
    assert Tron(CustomProvider(NODE)).get_latest_block_number() == 7


@pytest.mark.asyncio
async def test_custom_provider_from_async_code():
    assert await Tron(CustomProvider(NODE)).get_latest_block_number() == 7
