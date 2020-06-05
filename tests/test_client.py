from tronpy import Tron


def test_client():
    client = Tron()

    print(client)

    txn = (
        client.trx.transfer("TTMNxTmRpBZnjtUnohX84j25NLkTqDga7j", "TLtbfrrQMXixJkf3Z3cEXfPeY5erKXDnbj", 1_000000)
        .memo("test transaction")
        .build()
        .inspect()
        .broadcast()
    )
