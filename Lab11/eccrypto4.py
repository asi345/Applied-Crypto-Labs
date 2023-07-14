from __future__ import annotations

from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Hash import SHA256
from typing import Tuple

import modsqrt
from secrets import randbelow

DEFAULT_CURVE_NAME = "secp256k1"


class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __eq__(self, other):
        if isinstance(other, EllipticCurvePoint):
            return self.x == other.x and self.y == other.y
        return False


class EllipticCurve:
    CurveList = {
        "secp256k1": {
            "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
            "a": 0x0000000000000000000000000000000000000000000000000000000000000000,
            "b": 0x0000000000000000000000000000000000000000000000000000000000000007,
            "G": (
                0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
            ),
            "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
            "h": 0x1,
        },
        "secp256r1": {
            "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
            "a": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
            "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
            "G": (
                0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
                0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
            ),
            "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
            "h": 0x1,
        },
    }

    def __init__(self, curve_name):
        self.curve_name = curve_name
        assert curve_name in self.CurveList
        curve = self.CurveList[curve_name]
        self.G = EllipticCurvePoint(self, curve["G"][0], curve["G"][1])
        self.p = curve["p"]
        self.n = curve["n"]
        self.a = curve["a"]
        self.b = curve["b"]
        self.zero = EllipticCurvePoint(self, 0, 0)

    def point(self, x, y) -> EllipticCurvePoint:
        return EllipticCurvePoint(self, x, y)


class EllipticCurvePoint(Point):
    def __init__(self, curve: EllipticCurve, x, y):
        self.curve = curve
        super().__init__(x, y)

    def __eq__(self, other):
        if isinstance(other, EllipticCurvePoint):
            return super(EllipticCurvePoint, self).__eq__(other)
        return False

    def __repr__(self):
        return f"Point({self.x}, {self.y})"

    def double(self) -> EllipticCurvePoint:
        if self.y == 0 and self.x == 0:
            return self.curve.zero
        lamb = (3 * self.x * self.x + self.curve.a) * pow(2 * self.y, -1, self.curve.p) % self.curve.p
        x3 = (lamb * lamb - 2 * self.x) % self.curve.p
        y3 = (lamb * (self.x - x3) - self.y) % self.curve.p
        return EllipticCurvePoint(self.curve, x3, y3)
        
    def add(self, Q: EllipticCurvePoint) -> EllipticCurvePoint:
        if self.x != Q.x:
            lamb = (Q.y - self.y) * pow(Q.x - self.x, -1, self.curve.p) % self.curve.p
            x3 = (lamb * lamb - self.x - Q.x) % self.curve.p
            y3 = (lamb * (self.x - x3) - self.y) % self.curve.p
            return EllipticCurvePoint(self.curve, x3, y3)
        elif self.y == Q.y:
            return self.double()
        else:
            return self.curve.zero

    def scalar_mult(self, n: int) -> EllipticCurvePoint:
        Q = EllipticCurvePoint(self.curve, self.x, self.y)
        multiplier = list(bin(n)[3:])
        for bit in multiplier:
            Q = Q.double()
            if bit == '1':
                Q = Q.add(self)
        return Q

    def to_bytes(self, compression: bool = False) -> bytes:
        if not compression:
            return b'\x04' + self.x.to_bytes((self.curve.p.bit_length() + 7) // 8, 'big') + self.y.to_bytes((self.curve.p.bit_length() + 7) // 8, 'big')
        else :
            if self.y % 2 == 0:
                return b'\x02' + self.x.to_bytes((self.curve.p.bit_length() + 7) // 8, 'big')
            else:
                return b'\x03' + self.x.to_bytes((self.curve.p.bit_length() + 7) // 8, 'big')

    @staticmethod
    def from_bytes(curve: EllipticCurve, bs: bytes) -> EllipticCurvePoint:
        bound = (curve.p.bit_length() + 7) // 8
        if bs[0] == 0x04:
            x = int.from_bytes(bs[1:bound + 1], 'big')
            y = int.from_bytes(bs[bound + 1:], 'big')
        else:
            x = int.from_bytes(bs[1:], 'big')
            y2 = (pow(x, 3, curve.p) + curve.a * x + curve.b) % curve.p
            y = modsqrt.modular_sqrt(y2, curve.p)
            if (bs[0] == 0x02 and y % 2 == 1) or (bs[0] == 0x03 and y % 2 == 0):
                y = curve.p - y
        return EllipticCurvePoint(curve, x, y)


class ECDSA:
    def __init__(self, curve_name: str = DEFAULT_CURVE_NAME):
        self.ec = EllipticCurve(curve_name)
        self.d = None
        self.public_point = None

    def keygen(self):
        self.d = randbelow(self.ec.n)
        self.public_point = self.ec.G.scalar_mult(self.d)

    # please use SHA256 as the hash function
    def sign(self, msg_bytes: bytes) -> Tuple[bytes, bytes]:
        k = randbelow(self.ec.n)
        r = (self.ec.G.scalar_mult(k).x % self.ec.p) % self.ec.n
        s = (pow(k, -1, self.ec.n) * (int.from_bytes(SHA256.new(msg_bytes).digest(), 'big') + self.d * r)) % self.ec.n
        return long_to_bytes(r) , long_to_bytes(s)

    # public_point_bytes can be in both compressed and de-compressed form, need to check
    def verify(
        self,
        msg_bytes: bytes,
        r_bytes: bytes,
        s_bytes: bytes,
        public_point_bytes: bytes,
    ) -> bool:
        r = bytes_to_long(r_bytes)
        s = bytes_to_long(s_bytes) % self.ec.n
        public_point = EllipticCurvePoint.from_bytes(self.ec, public_point_bytes)
        if not (1 <= r <= self.ec.n - 1 and 1 <= s <= self.ec.n - 1):
            return False
        w = pow(s, -1, self.ec.n)
        hm = int.from_bytes(SHA256.new(msg_bytes).digest(), 'big') % self.ec.n
        u1 = (w * hm) % self.ec.n
        u2 = (w * r) % self.ec.n
        return self.ec.G.scalar_mult(u1).add(public_point.scalar_mult(u2)).x % self.ec.n == r
