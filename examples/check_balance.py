from pprint import pprint

from tronpy import Tron
from tronpy.exceptions import AddressNotFound

client = Tron()


def check_balance(address):
    try:
        return client.get_account_balance(address)
    except AddressNotFound:
        return "Adress not found..!"


pprint(check_balance("<address>"))
