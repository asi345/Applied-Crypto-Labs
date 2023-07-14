#M1
import telnetlib
import json
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES

CURVE_NAME = "secp256r1"
CURVE_P_LEN = 32

host = 'aclabs.ethz.ch'
PORT = 51201

#Remote server communication functions
def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

def point_to_bytes(point: ECC.EccPoint):
    y = int(point.y).to_bytes(CURVE_P_LEN, "big")
    x = int(point.x).to_bytes(CURVE_P_LEN, "big")
    return x + y

tn = telnetlib.Telnet(host, PORT)

#Get the public key
request = {
    'command': 'get_public_key'
}
json_send(request)
response = json_recv()
slt_Qx = int(response['x'])
slt_Qy = int(response['y'])
slt_Q = ECC.EccPoint(slt_Qx, slt_Qy, curve=CURVE_NAME)
slt_pubkey = ECC.EccKey(curve=CURVE_NAME, point=slt_Q)
server_signer = DSS.new(slt_pubkey, "fips-186-3")

point = ECC.EccPoint(0, 0, curve=CURVE_NAME)

#Send client hello
request = {
    'command': 'client_hello',
    'id': 'xd',
    'eph_x': 0,
    'eph_y': 0
}
json_send(request)
response = json_recv()
speh_Qx = int(response['eph_x'])
speh_Qy = int(response['eph_y'])
speh_Q = ECC.EccPoint(speh_Qx, speh_Qy, curve=CURVE_NAME)
signature = bytes.fromhex(response['signature'])

shared = point
key_raw = point_to_bytes(shared)
shared_key = HKDF(
    master=key_raw,
    salt=None,
    key_len=32,
    hashmod=SHA256,
    context=b"aead encryption",
)

tester = {
    'secure_command': 'time'
}

nonce = 0
cipher = AES.new(shared_key, AES.MODE_GCM, nonce=nonce.to_bytes(8, "big"))
enc_res, tag = cipher.encrypt_and_digest(json.dumps(tester).encode())

request = {
    'command': 'secure_command',
    'enc_payload': enc_res.hex(),
    'tag': tag.hex(),
    'nonce': nonce
}
nonce += 1
json_send(request)
response = json_recv()
enc_res = bytes.fromhex(response['enc_res'])
tag = bytes.fromhex(response['tag'])
signature = bytes.fromhex(response['signature'])

cipher = AES.new(shared_key, AES.MODE_GCM, nonce=nonce.to_bytes(8, "big"))
payload = cipher.decrypt_and_verify(enc_res, tag).decode()
print(payload)