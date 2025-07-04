import time


def current_timestamp() -> int:
    """
    Return the current time in milliseconds since the Unix epoch.

    Returns:
        int: The current timestamp in milliseconds.
    """
    return int(time.time() * 1000)


def get_ref_block_bytes(ref_block_id: str) -> str:
    """
    Extracts a 4-character substring from positions 12 to 15 of the given reference block ID.

    Parameters:
        ref_block_id (str): The reference block ID string.

    Returns:
        str: The 4-character substring representing the reference block bytes.
    """
    return ref_block_id[12:16]


def get_ref_block_hash(ref_block_id: str) -> str:
    """
    Extract the 16-character reference block hash from a block ID string.

    Parameters:
        ref_block_id (str): The block ID string to extract the hash from.

    Returns:
        str: The 16-character substring representing the reference block hash.
    """
    return ref_block_id[16:32]
