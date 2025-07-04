import time


def current_timestamp() -> int:
    return int(time.time() * 1000)


def get_ref_block_bytes(ref_block_id: str) -> str:
    return ref_block_id[12:16]


def get_ref_block_hash(ref_block_id: str) -> str:
    return ref_block_id[16:32]
