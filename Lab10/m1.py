#M1
import telnetlib
import json
import secrets

host = 'aclabs.ethz.ch'
PORT = 51001

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

#Info: Deterministic MAC function, so verify() is just using tag()
#Key derivation is not salted
#Encryption is AES CTR mode, however we have the power to choose the nonce
#Keys are fixed per connection, only created in creation of the class
#Since plaintext is 15 bytes, the encryption part of the ciphertext is also always 15 bytes
#Therefore, for 2 different messages with same nonce, XORing the ciphertexts will give us the XOR of the plaintexts
#Choose one plaintext as random 15 bytes, other will be "Give me a flag!"
#XORing them will give the XOR of ciphertexts, so we can create a ciphertext for "Give me a flag!"(Without MAC)

p = 2**127 - 1
TAG_LEN = 16

m1 = "I love this lab"
m2 = b"Give me a flag!"
m3 = "I hate this lab"
nonce = secrets.token_bytes(8)

#Get ciphertext and tag for m1
request = {
    'command': 'encrypt',
    'message': m1,
    'nonce': nonce.hex()
}
json_send(request)
response = json_recv()
c1 = bytes.fromhex(response['ciphertext'])
t1 = bytes.fromhex(response['tag'])

#Get ciphertext for "Give me a flag!"
c2 = bytes([x ^ y ^ z for x, y, z in zip(m1.encode(), m2, c1)])

#Get ciphertext and tag for m3
request = {
    'command': 'encrypt',
    'message': m3,
    'nonce': nonce.hex()
}
json_send(request)
response = json_recv()
c3 = bytes.fromhex(response['ciphertext'])
t3 = bytes.fromhex(response['tag'])

#Afterwards, MAC can also be derived in a similar fashion, since for same nonce, 'mask' will be same in tag()
#len(message) is always fixed. Only non-fixed variable is 'c' and we can not forge without it.
#However, if we subtract two valid tags, we get:
#c1 * K**2 - c3 * K**2
#From here, since we know c1 and c3, we can derive K**2
#Then, we can produce a valid tag for "Give me a flag!" by using the same nonce and K**2 and adding tag of c1
#with c2 * K**2 - c1 * K**2, where c2 is the ciphertext for "Give me a flag!"
diff_tags = int.from_bytes(t1, "big") - int.from_bytes(t3, "big")
diff_ciphertexts = int.from_bytes(c1, "big") - int.from_bytes(c3, "big")
k_sqr = diff_tags * pow(diff_ciphertexts, -1, p) % p
t2 = (int.from_bytes(t1, "big") + (int.from_bytes(c2, "big") - int.from_bytes(c1, "big")) * k_sqr) % p

#Send the forged ciphertext and tag
request = {
    'command': 'decrypt',
    'ciphertext': c2.hex(),
    'tag': t2.to_bytes(TAG_LEN, "big").hex(),
    'nonce': nonce.hex()
}
json_send(request)
response = json_recv()
print(response['res'])