import asyncio
import os
import secrets
import sys
from collections.abc import Callable
from typing import Any, cast
from urllib.parse import urljoin

import httpx2
from httpx2 import Timeout
from universalasync import LoopLocal, wrap

from tronpy.exceptions import ApiError
from tronpy.version import VERSION

DEFAULT_TIMEOUT = 10.0
DEFAULT_API_KEYS = [
    "f92221d5-7056-4366-b96f-65d3662ec2d9",
    "1e0a625f-cfa5-43ee-ba41-a09db1aae55f",
    "f399168e-2259-481c-90fc-6b3d984c5463",
    "da63253b-aa9c-46e7-a4e8-22d259a8026d",
    "88c10958-af7b-4d5a-8eef-6e84bf5fb809",
    "169bb4b3-cbe8-449a-984e-80e9adacac55",
]


@wrap
class HTTPProvider:
    """An HTTP Provider for API request.

    :param endpoint_uri: HTTP API URL base. Default value is ``"https://api.trongrid.io/"``. Can also be configured via
        the ``TRONPY_HTTP_PROVIDER_URI`` environment variable.
    :param timeout: HTTP timeout in seconds. Not applied to clients passed through ``client`` or ``client_factory``.
    :param client: ``httpx2.AsyncClient`` to use on the current event loop. Any other event loop gets a default client
        using ``timeout``, including those of other threads and of any later ``asyncio.run``. To use custom settings on
        every event loop, pass ``client_factory`` instead.
    :param api_key: TronGRID API Key in str, or list of str.
    :param jw_token: TronGRID JWT Credentials in str.
    :param client_factory: Function returning a new ``httpx2.AsyncClient``, called once per event loop. The provider closes
        the clients it returns. Can't be combined with ``client``.
    """

    def __init__(
        self,
        endpoint_uri: str | dict | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        *,
        client: httpx2.AsyncClient | None = None,
        api_key: str | list[str] | None = None,
        jw_token: str | None = None,
        client_factory: Callable[[], httpx2.AsyncClient] | None = None,
    ):
        super().__init__()

        if client is not None and client_factory is not None:
            raise ValueError("pass either client or client_factory, not both")

        if endpoint_uri is None:
            self.endpoint_uri: str = os.environ.get("TRONPY_HTTP_PROVIDER_URI", "https://api.trongrid.io/")
        elif isinstance(endpoint_uri, (dict,)):
            self.endpoint_uri = endpoint_uri["fullnode"]
        elif isinstance(endpoint_uri, (str,)):
            self.endpoint_uri = endpoint_uri
        else:
            raise TypeError(f"unknown endpoint uri {endpoint_uri}")

        if "trongrid" in self.endpoint_uri:
            self.use_api_key = True
            if isinstance(api_key, (str,)):
                self._api_keys = [api_key]
            elif isinstance(api_key, (list,)) and api_key:
                self._api_keys = api_key
            else:
                self._api_keys = DEFAULT_API_KEYS.copy()

            self._default_api_keys = self._api_keys.copy()
        else:
            self.use_api_key = False
        self.jw_token = jw_token

        self._client_factory = client_factory
        self._clients: LoopLocal[httpx2.AsyncClient] = LoopLocal(httpx2.AsyncClient.aclose)
        if client is not None:
            self._clients.get(lambda: client)

        self.timeout = timeout
        """Request timeout in second."""

    @property
    def client(self) -> httpx2.AsyncClient:
        """The ``httpx2.AsyncClient`` of the current event loop."""
        return self._clients.get(self._create_client)

    def _create_client(self) -> httpx2.AsyncClient:
        if self._client_factory is not None:
            return self._client_factory()
        return httpx2.AsyncClient(timeout=Timeout(self.timeout))

    async def make_request(self, method: str, params: Any = None) -> dict:
        headers = {"User-Agent": f"Tronpy/{VERSION}"}
        if self.use_api_key:
            headers["Tron-Pro-Api-Key"] = self.random_api_key

        if self.jw_token is not None:
            headers["Authorization"] = f"Bearer {self.jw_token}"

        if params is None:
            params = {}
        url = urljoin(self.endpoint_uri, method)
        resp = await self.client.post(headers=headers, url=url, json=params)

        if self.use_api_key and resp.status_code == 403 and b"Exceed the user daily usage" in resp.content:
            print("W:", resp.json().get("Error", "rate limit!"), file=sys.stderr)
            await self._handle_rate_limit(headers["Tron-Pro-Api-Key"])
            return await self.make_request(method, params)

        resp.raise_for_status()
        return cast(dict, resp.json())

    @property
    def random_api_key(self) -> str:
        try:
            return secrets.choice(self._api_keys)
        except IndexError as e:
            raise ApiError("rate limit! please add more API keys") from e

    async def _handle_rate_limit(self, used_key: str) -> None:
        if len(self._api_keys) > 0:
            self._api_keys.remove(used_key)
        else:
            print("W: Please add as-many API-Keys in HTTPProvider", file=sys.stderr)
            await asyncio.sleep(0.9)

    async def close(self) -> None:
        """Close the clients of all event loops."""
        await self._clients.close()
