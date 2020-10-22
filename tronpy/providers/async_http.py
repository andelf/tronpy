import os
from urllib.parse import urljoin
from typing import Any, Union

import httpx
from httpx import Timeout

DEFAULT_TIMEOUT = 10.0


class AsyncHTTPProvider(object):
    """An Async HTTP Provider for API request.

    :params endpoint_uri: HTTP API URL base. Default value is ``"https://api.trongrid.io/"``. Can also be configured via
        the ``TRONPY_HTTP_PROVIDER_URI`` environment variable.
    """

    def __init__(
        self, endpoint_uri: Union[str, dict] = None, timeout: float = DEFAULT_TIMEOUT, client: httpx.AsyncClient = None
    ):
        super().__init__()

        if endpoint_uri is None:
            self.endpoint_uri = os.environ.get("TRONPY_HTTP_PROVIDER_URI", "https://api.trongrid.io/")
        elif isinstance(endpoint_uri, (dict,)):
            self.endpoint_uri = endpoint_uri["fullnode"]
        elif isinstance(endpoint_uri, (str,)):
            self.endpoint_uri = endpoint_uri
        else:
            raise TypeError("unknown endpoint uri {}".format(endpoint_uri))

        headers = {"User-Agent": "Tronpy/0.2.0"}
        if client is None:
            self.client = httpx.AsyncClient(headers=headers, timeout=Timeout(timeout))
        else:
            self.client = client

        self.timeout = timeout
        """Request timeout in second."""

    async def make_request(self, method: str, params: Any = None) -> dict:
        if params is None:
            params = {}
        url = urljoin(self.endpoint_uri, method)
        resp = await self.client.post(url, json=params)
        resp.raise_for_status()
        return resp.json()
