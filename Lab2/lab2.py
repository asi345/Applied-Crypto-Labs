#A0
s = 'flag'
b = s.encode()
diff = 16 - (len(b) % 16)
b += diff.to_bytes() * diff
print(b.hex())

def padder(s):
    b = s.encode()
    diff = 16 - (len(b) % 16)
    b += diff.to_bytes() * diff
    return b

#M0
from remote import json_recv, json_send
request = {
    "command": "flag",
    "token": "534554454320415354524f4e4f4d59",
    "name": "Ata"
}
json_send(request)
response = json_recv()
print(response)

#M1
with open("aes.data", "r") as f:
    found = False
    for line in f:
        line = line.strip()
        curSet = set()
        count = len(line) // 32
        for i in range(count):
            cur = line[(i - 1) * 32: i * 32]
            if cur in curSet:
                print(line)
                found = True
                break
            curSet.add(cur)
        if found:
            break

#M2.0
import telnetlib
import json
REMOTE = True
PORT = 50220
if REMOTE:
    host = "aclabs.ethz.ch"
else:
    host = "localhost"
tn = telnetlib.Telnet(host, PORT)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

s = padder("flag, please!")
request = {
    "command": "encrypt",
    "prepend_pad": s.hex()
}
json_send(request)
response = json_recv()
enc = response["res"]
i = 1
curs = []
while i * 32 <= len(enc):
    cur = bytes.fromhex(enc[(i - 1) * 32 : i * 32])
    curs.append(cur)
    i += 1

request = {
    "command": "solve",
    "ciphertext": curs[0].hex()
}
json_send(request)
response = json_recv()
print(response)

#M2.1
PORT = 50221
tn = telnetlib.Telnet(host, PORT)

def encrypt(s):
    request = {
        "command": "encrypt",
        "prepend_pad": s.encode().hex()
    }
    json_send(request)
    response = json_recv()
    enc = response["res"]
    return enc

def padderByte(s):
    b = s
    diff = 16 - (len(b) % 16)
    b += diff.to_bytes() * diff
    return b

def encryptByte(s):
    request = {
        "command": "encrypt",
        "prepend_pad": s.hex()
    }
    json_send(request)
    response = json_recv()
    enc = response["res"]
    return enc
'''
for count in range(5):
    size = len(encrypt(""))
    k = size // 32
    s = "0"
    while size == len(encrypt(s)):
        s += "0"
    s += "0"

    padEncLastByte = encrypt(s)
    k = len(padEncLastByte) // 32
    target = padEncLastByte[(k - 1) * 32:]

    found = 0
    for i in range(256) :
        b = padderByte(bytes([i]))
        comp = encryptByte(b)[:32]
        if comp == target:
            found = i
            break

    request = {
        "command": "solve",
        "solve": bytes([i]).decode()
    }
    json_send(request)
    response = json_recv()
    print(response)
response = json_recv()
print(response)

#M2.2
PORT = 50222
tn = telnetlib.Telnet(host, PORT)

result = "~"
size = len(encrypt(""))
s = "`"
while size == len(encrypt(s)):
    s += "`"
k = size // 32 + 1

while result[0] != "`":
    s += "`"

    padEncLastByte = encrypt(s)
    #k = len(padEncLastByte) // 32
    target = padEncLastByte[(k - 1) * 32 : k * 32]

    found = 0
    for i in range(256) :
        b = padderByte(bytes([i]) + result[:-1].encode()[:15])
        comp = encryptByte(b)[:32]
        if comp == target:
            found = i
            break
    result = bytes([found]).decode() + result
    print(result)
'''
#M3
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

def generate_aes_key(integer: int, key_length: int):
    seed = integer.to_bytes(2, byteorder='big')
    hash_object = SHA256.new(seed)
    aes_key = hash_object.digest()
    trunc_key = aes_key[:key_length]
    return trunc_key

def aes_cbc_encryption(plaintext: bytes, key: bytes, iv: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

iv = bytes.fromhex("e764ea639dc187d058554645ed1714d8")
with open("flag.enc", "r") as f:
    ciphertext = bytes.fromhex(f.read())

#2 bytes length of key seed, so try all seeds xd
for i in range(2 ** 16):
    key = generate_aes_key(i, 16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain = cipher.decrypt(ciphertext)
    try:
        plain = plain.decode()
        print(plain)
    except:
        continue