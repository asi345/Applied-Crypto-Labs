#M2
import telnetlib
import json
from Crypto.Util import number
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

host = 'aclabs.ethz.ch'
PORT = 51002

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

#Info: Both functions can only be called once
#I only have influence on g and p, but no influence on pk_other(bob_pubkey)
#We have much freedom on g and p, so we do not have to comply with DHIES and DLP rules
#As usual, take a random integer mod p as 'h'
#Then set g = h^{(p-1)/3} mod p. This makes G_q = {1, g, g^2} and makes order of G_q = 3
#But this means that public key of Bob and also the 'shared' value can only be 1 or g or g^2
#From this fact, we can easily recover symmetric key K by calling the same HKDF function
#with same values since 'shared' is compromised

#Set p as a random prime with 1024 bits, with (p - 1) divisible by 3
p = number.getPrime(1024)
while (p - 1) % 3 != 0:
    p = number.getPrime(1024)

#Just to guarantee that g is not falling into unaccepted values(0, 1, p-1), we check if 
#the answer from server contains 'bob_pubkey' field
response = {}
while 'bob_pubkey' not in response:
    #Set h as a random integer mod p
    h = number.getPrime(1024)
    #Set g as h^{(p-1)/2} mod p
    g = pow(h, (p-1)//3, p)
    G = [1, g, pow(g, 2, p)]

    #Send parameters
    request = {
        'command': 'set_params',
        'p': p,
        'g': g
    }
    json_send(request)
    response = json_recv()
pk_other = int(response['bob_pubkey'])

#Get encrypted flag
request = {
    'command': 'encrypt'
}
json_send(request)
response = json_recv()
y = int(response['pk'])
ciphertext = bytes.fromhex(response['ciphertext'])
tag = bytes.fromhex(response['tag'])
nonce = bytes.fromhex(response['nonce'])

#Recover symmetric key by recovering 'sk', since it can only have 3 values mod 3
#Note that this 'sk' is not the original one but rather original one mod 3
#But it is okay since 'shared' value will be the same as computed in the server, since
#our group order is 3
sk = G.index(y)
shared = pow(pk_other, sk, p)

#Do the same steps as the server to obtain same K
pk_bytes = y.to_bytes(512, "big")
shared_bytes = shared.to_bytes(512, "big")
pk_other_bytes = pk_other.to_bytes(512, "big")
K: bytes = HKDF(shared_bytes + pk_bytes + pk_other_bytes, 32, salt=b"", num_keys=1, context=b"dhies-enc", hashmod=SHA256) #type: ignore

#Now use AES GCM to decrypt the flag, using the given nonce
cipher = AES.new(K, AES.MODE_GCM, nonce=nonce)
flag = cipher.decrypt_and_verify(ciphertext, tag)
print(flag.decode())