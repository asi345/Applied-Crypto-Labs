#M0
import telnetlib
import json
import secrets
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512
from Crypto.Cipher import AES 

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

'''
host = "aclabs.ethz.ch"
#host = 'localhost'
PORT = 50900
tn = telnetlib.Telnet(host, PORT)


p = 138310982169121381747558764122597210619210738340480962702891175829920658207142294773845187946443544844137496731905524601629446808922823844556308145855101223795300091047881311965153195052528173768386853113976906273825086867518698614505991374282596595726359327494708474529010276666804247171201845149294440548867
g = 35347793643784512578718068065261632028252678562130034899045619683131463682036436695569758375859127938206775417680940187580286209291486550218618469437205684892134361929336232961347809792699253935296478773945271149688582261042870357673264003202130096731026762451660209208886854748484875573768029653723060009335
kq = p - 1

request = {
    'command': 'alice_initialisation'
}
json_send(request)
response = json_recv()
a_resp = response['resp']
a_pub = int(response['alice_key'])

pub = pow(g, p - 1, p)

request = {
    'command': 'bob_initialisation',
    'alice_hello': {
        'resp': a_resp,
        'alice_key': 1
    }
}
json_send(request)
response = json_recv()
b_resp = response['resp']
b_pub = int(response['bob_key'])

request = {
    'command': 'alice_finished',
    'bob_hello': {
        'resp': b_resp,
        'bob_key': 1
    }
}
json_send(request)
response = json_recv()
cf = bytes.fromhex(response['encrypted_flag'])
nonce = bytes.fromhex(response['nonce'])

one = 1
shared = one.to_bytes(one.bit_length(), 'big')
secure_key = HKDF(master = shared, key_len = 32, salt = b'Secure alice and bob protocol', hashmod = SHA512, num_keys = 1)
cipher = AES.new(secure_key, AES.MODE_CTR, nonce=nonce)
f = cipher.decrypt(cf)
print(f)
'''
print('flag{Oh_n0_1_f0rg0t_t0_do_sanity_checks_on_the_keys}')

#M1
from Crypto.PublicKey import ElGamal
import elgamal

'''
host = "aclabs.ethz.ch"
PORT = 50901
tn = telnetlib.Telnet(host, PORT)

#this is key_dec's public key
request = {
    'command': 'get_public_key'
}
json_send(request)
response = json_recv()

p = int(response["p"])
g = int(response["g"])
secret = secrets.randbelow(p)
pub_2 = pow(g, secret, p)

key_dec_pub = ElGamal.construct((p, g, int(response["y"])))
my_key = ElGamal.construct((p, g, pub_2, secret))

request = {
    'command': 'set_response_key',
    'p': str(p),
    'g': str(g),
    'y': str(pub_2)
}
json_send(request)
response = json_recv()

#need to get encryption of m = b'backdoor' under server's key_dec which is not changeable
#to do that, encrypt with the key_dec you obtained

c = elgamal.ElGamalImpl.encrypt(key_dec_pub, b'backdoor')
request = {
    'command': 'encrypted_command',
    'encrypted_command': {
        'c1': c[0].hex(),
        'c2': c[1].hex()
    }
}
json_send(request)
response = json_recv()['encrypted_res']

c1 = bytes.fromhex(response['c1'])
c2 = bytes.fromhex(response['c2'])
m = elgamal.ElGamalImpl.decrypt(my_key, c1, c2)
print(m)
'''
print('flag{FlyingGrades}')

#M2
from Crypto.Util.number import inverse
'''
host = "aclabs.ethz.ch"
PORT = 50902
tn = telnetlib.Telnet(host, PORT)

#this is key_dec's public key
request = {
    'command': 'get_public_parameters'
}
json_send(request)
response = json_recv()

p = int(response["p"])
g = int(response["g"])

#send encrypt(1, b'') which results in (g^r, 0)
#server decrypts to message = 0 again
#then you get for new random r1, (g^r1, g^ra * int(b"The command you tried to execute was not recognized: "))
#you then send (g^r1, g^ra * int(b'backdoor')) by calculating
# int(b"The command you tried to execute was not recognized: ")^-1 * (int(b'backdoor'))

my_key = ElGamal.construct((p, g, 1))
c = elgamal.ElGamalImpl.encrypt(my_key, b'')

request = {
    'command': 'encrypted_command',
    'encrypted_command': {
        'c1': c[0].hex(),
        'c2': c[1].hex()
    }
}
json_send(request)
response = json_recv()['encrypted_res']

c1 = response['c1']
c2 = int.from_bytes(bytes.fromhex(response['c2']))

org = int.from_bytes(b"The command you tried to execute was not recognized: \x00")
target = int.from_bytes(b'backdoor')
mult = (target * inverse(org, p)) % p
c2 = (c2 * mult) % p
c2 = c2.to_bytes(c2.bit_length()//8 + 1, 'big')

k = secrets.randbelow(p)
pub_k = pow(g, k, p)
valid_key = ElGamal.construct((p, g, pub_k, k))
request = {
    'command': 'set_response_key',
    'p': str(p),
    'g': str(g),
    'y': str(pub_k)
}
json_send(request)
response = json_recv()

request = {
    'command': 'encrypted_command',
    'encrypted_command': {
        'c1': c1,
        'c2': c2.hex()
    }
}
json_send(request)
response = json_recv()['encrypted_res']

c1 = bytes.fromhex(response['c1'])
c2 = bytes.fromhex(response['c2'])
m = elgamal.ElGamalImpl.decrypt(valid_key, c1, c2)
print(m)
'''
print('flag{MultiplyAndConquer}')