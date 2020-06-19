from tronpy import Tron
from pprint import pprint


client = Tron()
pprint(client.generate_address())
