import json

from telnetlib import Telnet
from typing import List
from Crypto.Hash import SHA256
import math

from eccrypto5 import ECDSA
from bitarray import bitarray

REMOTE = True

ECDSAinstance = ECDSA()
ECDSAinstance.keygen()


def readline(tn: Telnet):
    return tn.read_until(b"\n")


def json_recv(tn: Telnet):
    line = readline(tn)
    return json.loads(line.decode("utf-8"))


def json_send(tn: Telnet, req):
    request = json.dumps(req).encode("utf-8")
    tn.write(request + b"\n")


def signed_json_send(tn: Telnet, req: dict):
    req_str = json.dumps(req)

    public_point_compressed_bytes = ECDSAinstance.public_point.to_bytes(
        compression=True
    )
    signature = ECDSAinstance.sign(req_str.encode())

    obj = {
        "command": "signed_command",
        "signed_command": req,
        "public_point": public_point_compressed_bytes.hex(),
        "r": signature[0].hex(),
        "s": signature[1].hex(),
    }
    json_send(tn, obj)


# Use the following 3 functions to send commands to the server
def get_status(tn: Telnet):
    obj = {"command": "get_status"}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res


def get_debug_info(tn: Telnet):
    obj = {"command": "get_debug_info"}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res


def get_control(tn: Telnet, d: int):
    obj = {"command": "get_control", "d": d}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res

def attack(tn: Telnet):
    #If iteration time is fast, then either bit == 0 or (Q.x == P.x and Q.y == -P.y)
    #This means bit == 0 or Q == -P => Q == [q - 1]P
    #If iteration time is slow, then bit == 1 and (Q.x != P.x or Q == P)
    #This means bit == 1 for sure
    #Fast iterations generally take about 20K-30K cycles, while slow iterations take about 50K cycles
    #35K is a good threshold for determining the fast-slow boundary

    threshold = 35000

    challenge = get_debug_info(tn)
    msg_bytes = challenge['msg'].encode()
    r = int(challenge['r'], 16)
    s = int(challenge['s'], 16)
    timings = challenge["timings"]
    l = len(timings)

    hLen = math.ceil(ECDSAinstance.ec.n.bit_length() / 8)
    msg_hash = SHA256.new(msg_bytes).digest()[:hLen]
    hm = int.from_bytes(msg_hash, "big") % ECDSAinstance.ec.n

    d = bitarray('0' * l)
    for i, t in enumerate(timings):
        if t > threshold:
            d[i] = True

    zeros = []
    for i in range(l):
        if d[i] == False:
            zeros.append(i)

    lz = len(zeros)
    for trial in range(2 ** lz):
        k = d.copy()
        for zindex in zeros:
            if (1 << zindex & trial) != 0:
                k[zindex] = True
        k.reverse()
        k = int(k.to01(), 2)
        guess = ((s * k - hm) * pow(r, -1, ECDSAinstance.ec.n)) % ECDSAinstance.ec.n
        res = get_control(tn, guess)
        if 'res' in res and 'Nope' not in res['res']:
            print(res['res'])
            break
        

if __name__ == "__main__":
    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
    else:
        HOSTNAME = "localhost"
    PORT = 51102
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
