from tronpy import Tron
from tronpy.keys import PrivateKey


def test_client_keygen():
    client = Tron()
    print(client.generate_address())
    print(client.get_address_from_passphrase('A'))


def test_client():
    client = Tron(network='nile')

    print(client)
    priv_key = PrivateKey(bytes.fromhex("8888888888888888888888888888888888888888888888888888888888888888"))

    txn = (
        client.trx.transfer("TJzXt1sZautjqXnpjQT4xSCBHNSYgBkDr3", "TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA", 1_000)
        .memo("test memo")
        .fee_limit(100_000_000)
        .build()
        .inspect()
        .sign(priv_key)
        .broadcast()
    )

    print(txn)


def test_client():
    client = Tron()

    print(client)
    priv_key = PrivateKey(bytes.fromhex("ebf7c9cad1ca710553c22669fd3c7c70832e7024c1a32da69bbc5ad19dcc8992"))

    """
    txn = (
        client.trx.asset_issue(
            "TGxv9UXRNMh4E6b33iuH1pqJfBffz6hXnV", "BTCC", 1_0000_0000_000000, url="https://www.example.com"
        )
        .memo("test issue BTCC coin")
        .fee_limit(0)
        .build()
        .inspect()
        .sign(priv_key)
        # .broadcast()
    )

    print(txn)
    """

    # print(client.get_account_permission("TGxv9UXRNMh4E6b33iuH1pqJfBffz6hXnV"))

    # very old address, of mainnet
    # print(client.get_account_resource("TTjacDH5PL8hpWirqU7HQQNZDyF723PuCg"))
    # "TGj1Ej1qRzL9feLTLhjwgxXF4Ct6GTWg2U"))

    cntr = client.get_contract("TMDRdYAcXbQDajbGFy4rgXcNLYswuYsfk1")
    print(cntr)

    print(cntr.abi)
    # print(client.get_contract("TTjacDH5PL8hpWirqU7HQQNZDyF723PuCg"))

    cntr.functions.name()


def test_client():
    client = Tron(network='nile')

    priv_key = PrivateKey(bytes.fromhex("ebf7c9cad1ca710553c22669fd3c7c70832e7024c1a32da69bbc5ad19dcc8992"))

    txn = (
        client.trx.asset_transfer(
            "TGxv9UXRNMh4E6b33iuH1pqJfBffz6hXnV", "TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA", 1_000000, token_id=1000047
        )
        .memo("test transfer coin")
        .fee_limit(0)
        .build()
        .inspect()
        .sign(priv_key)
        .broadcast()
    )

    print(txn)
