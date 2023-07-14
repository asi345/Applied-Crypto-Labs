from itertools import cycle

KEY_STREAM = b" REDACTED "

CHALLENGE_PLAINTEXT = b" REDACTED "

def xor(a, b):
    if len(a) < len(b):
        a, b = b, a
    return bytes([i ^ j for i, j in zip(a, cycle(b))])

ctxt = xor(KEY_STREAM, CHALLENGE_PLAINTEXT)
print(ctxt.hex())
