from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from eth_abi import encode

from tronpy import AsyncTron, Tron
from tronpy.async_contract import AsyncContract, AsyncShieldedTRC20
from tronpy.async_tron import AsyncTransactionBuilder
from tronpy.contract import ShieldedTRC20
from tronpy.providers import AsyncHTTPProvider, HTTPProvider
from tronpy.tron import TransactionBuilder

SHIELDED_ADDR = "TEkQTDyZmbY6hngxdAsxzxy9r3bUNhRjdS"
T_ADDR = "TPX6HK2NRN4XKRX1JAhbC827bm7gMmy5w1"
Z_ADDR = "ztron1test"
ZKEY = {"ask": "aa", "nsk": "bb", "ovk": "cc", "ak": "dd", "nk": "ee"}
SCALING_FACTOR = 1000
ROOT = b"\x01" * 32
PATH = [bytes([i]) * 32 for i in range(32)]
ABI = [
    {
        "type": "function",
        "name": "scalingFactor",
        "inputs": [],
        "outputs": [{"type": "uint256", "name": ""}],
        "stateMutability": "view",
    },
    {
        "type": "function",
        "name": "getPath",
        "inputs": [{"type": "uint256", "name": "position"}],
        "outputs": [{"type": "bytes32", "name": ""}, {"type": "bytes32[32]", "name": ""}],
        "stateMutability": "view",
    },
    {"type": "function", "name": "mint", "inputs": [], "outputs": [], "stateMutability": "nonpayable"},
    {"type": "function", "name": "transfer", "inputs": [], "outputs": [], "stateMutability": "nonpayable"},
    {"type": "function", "name": "burn", "inputs": [], "outputs": [], "stateMutability": "nonpayable"},
]
CONSTANT_RESULTS = {
    "scalingFactor()": encode(["uint256"], [SCALING_FACTOR]).hex(),
    "getPath(uint256)": encode(["bytes32", "bytes32[32]"], [ROOT, PATH]).hex(),
}


def node_response(method, params=None):
    if method == "wallet/getcontract":
        return {"bytecode": "00" * 64, "name": "Shielded", "abi": {"entrys": ABI}}
    if method == "wallet/getrcm":
        return {"value": "ff"}
    if method == "wallet/triggerconstantcontract":
        return {"constant_result": [CONSTANT_RESULTS[params["function_selector"]]]}
    if method == "wallet/createshieldedcontractparameters":
        return {"trigger_contract_input": "00"}
    if method == "wallet/isshieldedtrc20contractnotespent":
        return {}
    raise AssertionError(f"unexpected request {method}")


@pytest.fixture
def sync_node():
    with patch.object(HTTPProvider, "make_request", MagicMock(side_effect=node_response)) as mock:
        yield mock


@pytest_asyncio.fixture
async def shielded():
    with patch.object(AsyncHTTPProvider, "make_request", AsyncMock(side_effect=node_response)) as mock:
        async with AsyncTron(network="nile") as client:
            wrapper = await client.get_contract_as_shielded_trc20(SHIELDED_ADDR)
            wrapper.node = mock
            yield wrapper


def requests_to(node, method):
    return [call.args[1] for call in node.call_args_list if call.args[0] == method]


@pytest.mark.asyncio
async def test_async_client_returns_async_wrapper(shielded):
    assert isinstance(shielded, AsyncShieldedTRC20)


@pytest.mark.asyncio
async def test_async_lazy_properties_can_be_read_twice(shielded):
    assert await shielded.scale_factor == SCALING_FACTOR
    assert await shielded.scale_factor == SCALING_FACTOR
    assert len(requests_to(shielded.node, "wallet/triggerconstantcontract")) == 1

    trc20 = await shielded.trc20
    assert isinstance(trc20, AsyncContract)
    assert await shielded.trc20 is trc20


@pytest.mark.asyncio
async def test_async_mint(shielded):
    builder = await shielded.mint(T_ADDR, Z_ADDR, 2 * SCALING_FACTOR)
    assert isinstance(builder, AsyncTransactionBuilder)
    payload = requests_to(shielded.node, "wallet/createshieldedcontractparameters")[0]
    assert payload["shielded_receives"]["note"]["value"] == 2


@pytest.mark.asyncio
async def test_async_transfer(shielded):
    note = {"note": {"value": 2}, "position": 7}
    builder = await shielded.transfer(ZKEY, note, (Z_ADDR, 2))
    assert isinstance(builder, AsyncTransactionBuilder)
    spend = requests_to(shielded.node, "wallet/createshieldedcontractparameters")[0]["shielded_spends"][0]
    assert spend["root"] == ROOT.hex()
    assert spend["path"] == "".join(item.hex() for item in PATH)


@pytest.mark.asyncio
async def test_async_burn(shielded):
    note = {"note": {"value": 2}}
    builder = await shielded.burn(ZKEY, note, (T_ADDR, 2 * SCALING_FACTOR))
    assert isinstance(builder, AsyncTransactionBuilder)
    with pytest.raises(ValueError, match="Balance amount is wrong"):
        await shielded.burn(ZKEY, note, (T_ADDR, 1))


@pytest.mark.asyncio
async def test_async_is_note_spent_when_node_omits_the_field(shielded):
    assert await shielded.is_note_spent(ZKEY, {"note": {}}) is False


@pytest.mark.usefixtures("sync_node")
def test_sync_contract_as_shielded_trc20():
    client = Tron(network="nile")
    wrapper = client.get_contract(SHIELDED_ADDR).as_shielded_trc20()
    assert type(wrapper) is ShieldedTRC20
    assert isinstance(wrapper.mint(T_ADDR, Z_ADDR, 2 * SCALING_FACTOR), TransactionBuilder)
    assert wrapper.is_note_spent(ZKEY, {"note": {}}) is False
