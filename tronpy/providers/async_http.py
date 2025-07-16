import asyncio
import os
import secrets
import sys
from typing import Any, Union
from urllib.parse import urljoin

import httpx
from httpx import Timeout

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


class AsyncHTTPProvider:
    """An Async HTTP Provider for API request.

    :params endpoint_uri: HTTP API URL base. Default value is ``"https://api.trongrid.io/"``. Can also be configured via
        the ``TRONPY_HTTP_PROVIDER_URI`` environment variable.
    :param jw_token: TronGRID JWT Credentials in str.
    """

    def __init__(
        self,
        endpoint_uri: Union[str, dict] = None,
        timeout: float = DEFAULT_TIMEOUT,
        client: httpx.AsyncClient = None,
        api_key: Union[str, list[str]] = None,
        jw_token: str = None,
    ):
        super().__init__()

        if endpoint_uri is None:
            self.endpoint_uri = os.environ.get("TRONPY_HTTP_PROVIDER_URI", "https://api.trongrid.io/")
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

        if client is None:
            self.client = httpx.AsyncClient(timeout=Timeout(timeout))
        else:
            self.client = client

        self.timeout = timeout
        """Request timeout in second."""

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
        return resp.json()

    @property
    def random_api_key(self):
        try:
            return secrets.choice(self._api_keys)
        except IndexError as e:
            raise ApiError("rate limit! please add more API keys") from e

    async def _handle_rate_limit(self, used_key):
        if len(self._api_keys) > 0:
            self._api_keys.remove(used_key)
        else:
            print("W: Please add as-many API-Keys in HTTPProvider", file=sys.stderr)
            await asyncio.sleep(0.9)
