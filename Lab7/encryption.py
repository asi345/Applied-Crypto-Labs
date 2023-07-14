#!/usr/bin/env python

from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

...

class CBC_HMAC():
    def __init__(self, enc_key_len: int = 16, mac_key_len: int = 16, key: bytes = None):
        self.enc_key_len = enc_key_len
        self.mac_key_len = mac_key_len
        k = len(key)
        if k == 32:
            self.tag_len = 16
        elif k == 48:
            self.tag_len = 24
        elif k == 56:
            self.tag_len = 24
        else:
            self.tag_len = 32

        # a correctly sized key must always be provided by the caller
        if not len(key) == self.mac_key_len + self.enc_key_len:
            raise ValueError("Bad key len")

        self.mac_key = key[:self.mac_key_len]
        self.enc_key = key[-self.enc_key_len:]

        self.block_len = 16

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

    def encrypt(self, pt: bytes, add_data: bytes = b'', iv: bytes = None):
        """Compute ciphertext and MAC tag.

        Keyword arguments:
        pt       -- plaintext
        add_data -- additional data
        iv       -- initialization vector
        """
        plain = self._add_pt_padding(pt)

        if iv is None:
            iv = get_random_bytes(16)

        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(plain)
        l = (8 * len(add_data)).to_bytes(8)
        totag = add_data + iv + ct + l
        tag = HMAC.new(self.mac_key, totag, SHA256).digest()[:self.tag_len]

        return (iv + ct) + tag
    
    def decrypt(self, ct: bytes, add_data: bytes):
        iv = ct[:self.block_len]
        ctxt = ct[self.block_len:-self.tag_len]
        tag = ct[-self.tag_len:]

        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv=iv)
        pt = cipher.decrypt(ctxt)
        pt = self._remove_pt_padding(pt)
        return pt.decode()

def main():
    test_key = bytes.fromhex("""
        000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        """)
    test_pt = bytes.fromhex("""
        41206369706865722073797374656d206d757374206e6f742062652072657175
        6972656420746f206265207365637265742c20616e64206974206d7573742062
        652061626c6520746f2066616c6c20696e746f207468652068616e6473206f66
        2074686520656e656d7920776974686f757420696e636f6e76656e69656e6365
        """)
    test_iv = bytes.fromhex("1af38c2dc2b96ffdd86694092341bc04")
    test_ad = bytes.fromhex("""
        546865207365636f6e64207072696e6369706c65206f66204175677573746520
        4b6572636b686f666673
        """)
    test_c = bytes.fromhex("""
        1af38c2dc2b96ffdd86694092341bc04c80edfa32ddf39d5ef00c0b468834279
        a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2
        fc6f9b3f399a221489f16362c703233609d45ac69864e3321cf82935ac4096c8
        6e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078158ee5d79de59f
        bd34d848b3d69550a67646344427ade54b8851ffb598f7f80074b9473c82e2db
        652c3fa36b0a7c5b3219fab3a30bc1c4
        """)

    assert CBC_HMAC(16, 16, test_key).encrypt(test_pt, test_ad, test_iv) == test_c

    pt = b"Just plaintext\x02\x00"
    print(SHA256.new(
        data=CBC_HMAC(16, 16, test_key).encrypt(pt, iv=test_iv)
        ).hexdigest())

if __name__ == "__main__":
    main()
