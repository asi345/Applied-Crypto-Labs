import json

from telnetlib import Telnet
from typing import List

from eccrypto4 import ECDSA

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


def get_challenge(tn: Telnet):
    obj = {"command": "get_challenge"}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res


def reply_challenge(tn: Telnet, solution: List[bool]):
    obj = {"command": "backdoor", "solution": solution}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res


def attack(tn: Telnet):
    challenge = get_challenge(tn)
    public_point_bytes = bytes.fromhex(challenge["public_point"])
    solution = []
    for i in range(len(challenge['challenge'])):
        msg_bytes = challenge['challenge'][i]['msg'].encode()
        r_bytes = bytes.fromhex(challenge['challenge'][i]['r'])
        s_bytes = bytes.fromhex(challenge['challenge'][i]['s'])
        solution.append(ECDSAinstance.verify(msg_bytes, r_bytes, s_bytes, public_point_bytes))
    res = reply_challenge(tn, solution)
    print(res)

if __name__ == "__main__":
    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
    else:
        HOSTNAME = "localhost"
    PORT = 51101
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
