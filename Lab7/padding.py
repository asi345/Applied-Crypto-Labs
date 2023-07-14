#!/usr/bin/env python

from Crypto.Hash import SHA256

...

class CBC_HMAC():
    def __init__(self, enc_key_len: int = 16, mac_key_len: int = 16, key: bytes = None):
        ...

    def _add_pt_padding(self, pt: bytes):
        need = 16 - len(pt) % 16
        res = pt + bytes([need for _ in range(need)])
        return res

    def _remove_pt_padding(self, pt: bytes):
        padded = pt[-1]
        if padded < 1 or padded > 16:
            raise ValueError("Bad decryption")
        for i in range(2, padded + 1):
            if pt[-i] != padded:
                raise ValueError("Bad decryption")
        return pt[:-padded]


def main():
    aead = CBC_HMAC(16, 16, b''.join(bytes([i]) for i in range(32)))
    pt = b"Just plaintext\x02\x00"
    assert aead._remove_pt_padding(aead._add_pt_padding(pt)) == pt
    print(SHA256.new(data=aead._add_pt_padding(pt)).hexdigest())

if __name__ == "__main__":
    main()
