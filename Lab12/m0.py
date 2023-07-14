#M0
import telnetlib
import json
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA512

host = 'aclabs.ethz.ch'
PORT = 51200

#Remote server communication functions
def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

tn = telnetlib.Telnet(host, PORT)

p = 138310982169121381747558764122597210619210738340480962702891175829920658207142294773845187946443544844137496731905524601629446808922823844556308145855101223795300091047881311965153195052528173768386853113976906273825086867518698614505991374282596595726359327494708474529010276666804247171201845149294440548867
q = (p - 1) // 2
g = 3

#Get client nonce
request = {
    'command': 'client_hello'
}
json_send(request)
response = json_recv()
client_nonce = bytes.fromhex(response['client_nonce'])

#Get boss nonce and public key
request = {
    'command': 'boss_hello',
    'client_nonce': response['client_nonce']
}
json_send(request)
response = json_recv()
boss_nonce = bytes.fromhex(response['boss_nonce'])
boss_pub = int(response['pubkey'])

#Get client finished
request = {
    'command': 'client_finished',
    'boss_nonce': response['boss_nonce'],
    'pubkey': response['pubkey']
}
json_send(request)
response = json_recv()
c1 = int(response['encrypted_shared_key']['c1'])
c2 = int(response['encrypted_shared_key']['c2'])
ciphertext = bytes.fromhex(response['ciphertext'])
cipher_nonce = bytes.fromhex(response['nonce'])

#Get boss private key
request = {
    'command': 'compromise'
}
json_send(request)
response = json_recv()
boss_priv = int(response['secret'])

#Decrypt ciphertext
K = pow(c1, boss_priv, p)
shared_secret = (c2 * pow(K, -1, p)) % p
secure_key = HKDF(
                master=long_to_bytes(shared_secret),
                key_len=32,
                salt=client_nonce + boss_nonce,
                hashmod=SHA512,
                num_keys=1,
)
cipher = AES.new(secure_key, AES.MODE_CTR, nonce=cipher_nonce)
message = cipher.decrypt(ciphertext)
print(message)