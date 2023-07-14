from typing import Tuple
import secrets
from Crypto.PublicKey import ElGamal
from Crypto.Util import number


class ElGamalImpl:

    @classmethod
    def decrypt(cls, key: ElGamal.ElGamalKey, c1: bytes, c2: bytes) -> bytes:
        """Your decryption code goes here.

        Args:
            key (ElGamal.ElGamalKey): the ElGamal key used for decryption
            c1 (bytes): first component of an ElGamal ciphertext
            c2 (bytes): second component of an ElGamal ciphertext

        Returns:
            (bytes): the plaintext message
        """
        pub = int.from_bytes(c1)
        K = pow(pub, int(key.x), int(key.p))
        km = int.from_bytes(c2)
        key_inv = number.inverse(K, int(key.p))
        m = (key_inv * km) % int(key.p)
        return m.to_bytes(m.bit_length()//8 + 1, 'big')

    @classmethod
    def encrypt(cls, key: ElGamal.ElGamalKey, msg: bytes) -> Tuple[bytes, bytes]:
        """Your encryption code goes here.

        Args:
            key (ElGamal.ElGamalKey): the ElGamal key used for encryption
            msg (bytes): the plaintext message to be sent

        Returns:
            (bytes, bytes): c1 and c2 of an ElGamal ciphertext
        """
        priv = secrets.randbelow(int(key.p))
        pub = pow(int(key.g), priv, int(key.p))
        K = pow(int(key.y), priv, int(key.p))
        c = (K * int.from_bytes(msg)) % int(key.p)
        return (pub.to_bytes(pub.bit_length()//8 + 1, 'big'), c.to_bytes(c.bit_length()//8 + 1, 'big'))