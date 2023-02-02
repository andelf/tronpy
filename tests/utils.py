RAW_DATA_KEYS = {
    "contract",
    "timestamp",
    "expiration",
    "ref_block_bytes",
    "ref_block_hash",
    "fee_limit",
}


def check_transaction_structure(tx, expected, fee_limit, *, expect_signature=True, expect_memo=True):
    assert set(tx.keys()) == {"txID", "raw_data", "signature", "permission"}
    assert tx["permission"] is None
    assert set(tx["raw_data"].keys()) == (RAW_DATA_KEYS | {"data"} if expect_memo else RAW_DATA_KEYS)
    if fee_limit is not None:
        assert tx["raw_data"]["fee_limit"] == fee_limit
    assert len(tx["raw_data"]["contract"]) == 1
    contract = tx["raw_data"]["contract"][0]
    assert contract.items() >= expected.items()
    assert len(tx["signature"]) == (1 if expect_signature else 0)


def check_generate_address(data):
    assert set(data.keys()) == {"base58check_address", "hex_address", "private_key", "public_key"}
    assert len(data["private_key"]) == 64
    assert len(data["public_key"]) == 128
    assert len(data["hex_address"]) == 42
    assert len(data["base58check_address"]) == 34
