import telnetlib
import json
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

host = "aclabs.ethz.ch"
PORT = 50400

#Remote server communication functions
def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

#Info: key is 4 bytes, message is 16 bytes
#Actually 2 times 2 bytes key is used
#the 2 keys are the hashes of parts of the real key

#Using a fixed plaintext for all rounds, it does not matter
val = b'\x00' * 16

#Stores every possible encryption and the cipher doing that encryption for a 2-byte key
#This uses the fact that there are 2 individual 2-byte key
ciphers, encs = [], set()
for i in range(2 ** 16):
    pos_key = SHA256.new(i.to_bytes(2)).digest()
    cipher = AES.new(pos_key, AES.MODE_ECB)
    ciphers.append(cipher)
    encs.add(cipher.encrypt(val))

tn = telnetlib.Telnet(host, PORT)
count = 0
#checks the number of guesses made
while count < 64:
    #Gets the current challenge from the server
    request = {
        "command": "query",
        "m": val.hex()
    }
    json_send(request)
    response = json_recv()
    res = bytes.fromhex(response['res'])
    #Decides the guess
    #For each cipher we had stored(they cover all 2-byte key ciphers),
    #we decrypt the response using that cipher. If the decryption result
    #is in the set where all 2 byte-key encryptions of the plaintext is
    #stored, then this should be a valid encryption from the server and
    #the guess must be 0. Else it is 1.
    guess = 1
    for i in range(2 ** 16):
        cipher = ciphers[i]
        dec = cipher.decrypt(res)
        if dec in encs:
            guess = 0
            break
    request = {
        'command': 'guess',
        'b': guess
    }
    json_send(request)
    response = json_recv()
    #print(response)
    count += 1

request = {
    "command": "flag"
}
json_send(request)
response = json_recv()
print(response['flag'])