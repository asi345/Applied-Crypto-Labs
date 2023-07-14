#M0
import telnetlib
import json
from Crypto.Hash import MD5, HMAC, SHA256
from typing import Tuple
import math

host = 'aclabs.ethz.ch'
PORT = 51000

#Remote server communication functions
def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


#Info : Security of DSA under randomness failure slide in Lecture-26-27 slides, slide 22

#Since get_nonce() is a deterministic function, the outputs of get_nonce() will be same for same inputs
#This means that 'k' and 'r' will be the same for two different signatures. Then we can recover the
#signing key 'x' by the attack described in the lecture

#But notice that get_nonce() also uses sign_key, which is fixed per connection and msg. To get the same
#outcome, we need to give two messages such that they generate same MD5 hash. I will use the strings
#I used earlier in Lab

collision1 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70')
collision2 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70')

tn = telnetlib.Telnet(host, PORT)
#Get parameters
request = {
    'command': 'get_params'
}
json_send(request)
response = json_recv()
y = int(response['vfy_key'])
g = int(response['g'])
p = int(response['p'])
q = int(response['q'])

#Get two signatures
request = {
    'command': 'sign',
    'message': collision1.hex()
}
json_send(request)
response = json_recv()
r1 = int(response['r'])
s1 = int(response['s'])

request = {
    'command': 'sign',
    'message': collision2.hex()
}
json_send(request)
response = json_recv()
r2 = int(response['r'])
s2 = int(response['s'])

H1 = int.from_bytes(SHA256.new(collision1).digest(), "big")
H2 = int.from_bytes(SHA256.new(collision2).digest(), "big")

#First we find 'k' as follows:
#s_1 - s_2 = k^{-1} (H(m_1) - H(m_2)) mod q
#k = (H(m_1) - H(m_2)) (s_1 - s_2)^{-1} mod q
k = ((H1 - H2) * pow((s1 - s2), -1, q)) % q

#Then we find 'x' as follows:
#x = (s_1 * k - H(m_1)) * r^{-1} mod q
x = ((s1 * k - H1) * pow(r1, -1, q)) % q

#Now we can sign the message: b"Give me a flag!"
#To be accurate, I will use the functions from the server
def get_nonce(msg: bytes, sign_key: int, g: int, p: int, q: int) -> Tuple[int, int]:
    # Because we don't trust our server, we will be hedging against randomness failures by derandomising

    h = MD5.new(msg).digest()

    # We begin by deterministically deriving a nonce
    # as specified in https://datatracker.ietf.org/doc/html/rfc6979#section-3.2
    l = 8 * MD5.digest_size
    rlen = math.ceil(q.bit_length() / 8)
    V = bytes([1] * l)
    K = bytes([0] * l)

    K = HMAC.new(K, V + b'\x00' + sign_key.to_bytes(rlen, "big") + h).digest()
    V = HMAC.new(K, V).digest()
    K = HMAC.new(K, V + b'\x01' + sign_key.to_bytes(rlen, "big") + h).digest()
    V = HMAC.new(K, V).digest()

    while True:
        T = b''
        tlen = 0

        while tlen < q.bit_length():
            V = HMAC.new(K, V).digest()
            T += V
            tlen += len(V) * 8

        # Apply bits2int and bring down k to the length of q
        k = int.from_bytes(T, "big")
        k >>= k.bit_length() - q.bit_length()

        r = pow(g, k, p) % q

        if 1 <= k <= q-1 and r != 0:
            break

        K = HMAC.new(K, V + b'\x00').digest()
        V = HMAC.new(K, V).digest()

    return k, r


def DSA_sign(msg: bytes, sign_key: int, g: int, p: int, q: int):
    # Get k and r = (g^k mod p) mod q
    k, r = get_nonce(msg, sign_key, g, p, q)

    # Compute the signature
    h = int.from_bytes(SHA256.new(msg).digest(), "big")
    s = (pow(k, -1, q) * (h + sign_key * r)) % q
    return r, s

#Now we are ready to deploy
r, s = DSA_sign(b"Give me a flag!", x, g, p, q)
request = {
    'command': 'flag',
    'r': r,
    's': s
}
json_send(request)
response = json_recv()
print(response['flag'])