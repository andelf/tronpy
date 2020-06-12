import os
import requests
from urllib.parse import urljoin
from typing import Any, Union


class HTTPProvider(object):
    def __init__(self, endpoint_uri: Union[str, dict] = None):
        super().__init__()

        if endpoint_uri is None:
            self.endpoint_uri = os.environ.get(
                "TRONPY_HTTP_PROVIDER_URI", "https://api.trongrid.io/"
            )
        elif isinstance(endpoint_uri, (dict,)):
            self.endpoint_uri = endpoint_uri["fullnode"]
        elif isinstance(endpoint_uri, (str,)):
            self.endpoint_uri = endpoint_uri
        else:
            raise TypeError("unknown endpoint uri {}".format(endpoint_uri))

        self.sess = requests.session()
        self.sess.headers["User-Agent"] = "Tronpy/0.0.1"

    def make_request(self, method: str, params: Any = None) -> dict:
        if params is None:
            params = {}
        url = urljoin(self.endpoint_uri, method)
        resp = self.sess.post(url, json=params)
        resp.raise_for_status()
        return resp.json()
