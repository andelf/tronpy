def check_balance(address):
    try:
        balance=client.get_account_balance(address)
        return balance
    except AddressNotFound:
        return 'Adress not found..!'


print(check_balance('<address>'))
