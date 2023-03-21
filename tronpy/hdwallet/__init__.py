# Originally from: https://github.com/ethereum/web3.py
#

from eth_utils import ValidationError

from .deterministic import HDPath

TRON_DEFAULT_PATH = "m/44'/195'/0'/0/0"


def _import_mnemonic():
    try:
        from mnemonic import Mnemonic
    except ImportError as e:
        raise ImportError("Run `pip install tronpy[mnemonic]` to use mnemonic!") from e
    return Mnemonic


def generate_mnemonic(num_words: int, lang: str) -> str:
    Mnemonic = _import_mnemonic()
    words2strength = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}
    try:
        return Mnemonic(lang).generate(words2strength[num_words])
    except KeyError as e:
        raise ValueError(f"{num_words} not a valid number of words! Choose from {tuple(words2strength.keys())}") from e
    except Exception as e:
        raise e


def seed_from_mnemonic(words: str, passphrase: str) -> bytes:
    Mnemonic = _import_mnemonic()
    lang = Mnemonic.detect_language(words)
    expanded_words = Mnemonic(lang).expand(words)
    if not Mnemonic(lang).check(expanded_words):
        raise ValidationError(f"Provided words: '{expanded_words}', are not a valid BIP39 mnemonic phrase!")
    return Mnemonic.to_seed(expanded_words, passphrase)


def key_from_seed(seed: bytes, account_path: str):
    return HDPath(account_path).derive(seed)
