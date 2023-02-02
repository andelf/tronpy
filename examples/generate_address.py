from pprint import pprint

from tronpy import Tron

client = Tron()
pprint(client.generate_address())
