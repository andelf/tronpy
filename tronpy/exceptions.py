class BadAddress(ValueError):
    pass


class BadKey(ValueError):
    pass


class BadSignature(ValueError):
    pass


class BadHash(ValueError):
    pass


class TaposError(ValueError):
    pass


class UnknownError(Exception):
    pass


class TransactionError(Exception):
    pass


class ValidationError(Exception):
    pass


class ApiError(Exception):
    pass


class NotFound(ValueError):
    pass


class AddressNotFound(NotFound):
    pass


class TransactionNotFound(NotFound):
    pass