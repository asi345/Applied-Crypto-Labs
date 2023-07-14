from __future__ import annotations
from Crypto.Util.number import long_to_bytes

import modsqrt

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
            if bs[0] == 0x02 and y % 2 == 1 or bs[0] == 0x03 and y % 2 == 0:
                y = curve.p - y
        return EllipticCurvePoint(curve, x, y)

if __name__ == '__main__':
    ec = EllipticCurve('secp256k1')
    P = ec.point(
        6797664738401079993500032048020420187487016626020467949408987205636298574411,
        29393079371138059658683656475029497006421030687323960394391845889032119704627,
    )

    # test non compressed form
    assert EllipticCurvePoint.from_bytes(ec, P.to_bytes(compression=False)) == P

    print(P.to_bytes(compression=True).hex())
