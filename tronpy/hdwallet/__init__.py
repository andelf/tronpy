# Originally from: https://github.com/ethereum/web3.py
#

from eth_utils import (
    ValidationError,
)

from .deterministic import (
    HDPath,
)
from .mnemonic import (
    Mnemonic,
)

TRON_DEFAULT_PATH = "m/44'/195'/0'/0/0"


def generate_mnemonic(num_words: int, lang: str) -> str:
    words2strength = {12:128, 15:160, 18:192, 21:224, 24:224}
    return Mnemonic(lang).generate(words2strength[num_words])


def seed_from_mnemonic(words: str, passphrase: str) -> bytes:
    lang = Mnemonic.detect_language(words)
    expanded_words = Mnemonic(lang).expand(words)
    if not Mnemonic(lang).check(expanded_words):
        raise ValidationError(
            f"Provided words: '{expanded_words}', are not a valid BIP39 mnemonic phrase!"
        )
    return Mnemonic.to_seed(expanded_words, passphrase)


def key_from_seed(seed: bytes, account_path: str):
    return HDPath(account_path).derive(seed)