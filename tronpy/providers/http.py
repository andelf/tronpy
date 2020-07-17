import os
import requests
from urllib.parse import urljoin
from typing import Any, Union


DEFAULT_TIMEOUT = 10.0


class HTTPProvider(object):
    """An HTTP Provider for API request.

    :params endpoint_uri: HTTP API URL base. Default value is ``"https://api.trongrid.io/"``. Can also be configured via
        the ``TRONPY_HTTP_PROVIDER_URI`` environment variable.
    """

    def __init__(self, endpoint_uri: Union[str, dict] = None, timeout: float = DEFAULT_TIMEOUT):
        super().__init__()

        if endpoint_uri is None:
            self.endpoint_uri = os.environ.get("TRONPY_HTTP_PROVIDER_URI", "https://api.trongrid.io/")
        elif isinstance(endpoint_uri, (dict,)):
            self.endpoint_uri = endpoint_uri["fullnode"]
        elif isinstance(endpoint_uri, (str,)):
            self.endpoint_uri = endpoint_uri
        else:
            raise TypeError("unknown endpoint uri {}".format(endpoint_uri))

        self.sess = requests.session()
        self.sess.headers["User-Agent"] = "Tronpy/0.0.1"

        self.timeout = timeout
        """Request timeout in second."""

    def make_request(self, method: str, params: Any = None) -> dict:
        if params is None:
            params = {}
        url = urljoin(self.endpoint_uri, method)
        resp = self.sess.post(url, json=params, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()
