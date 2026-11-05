import pytest

from tronpy.defaults import CONF_NILE


@pytest.fixture(autouse=True)
def nile_fullnode(monkeypatch):
    monkeypatch.setitem(CONF_NILE, "fullnode", "https://nile.trongrid.io")
