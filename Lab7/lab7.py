#M4
'''
strs = ['a', 'a 23 bytes long string', '64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes']
res = []
for s in strs:
    l = (8 * len(s)).to_bytes(8).hex()
    res.append(l)
print(','.join(res))
'''

#M6
'''
from encryption import CBC_HMAC

crypto = CBC_HMAC(32, 24, bytes.fromhex('41206c6f6e6720726561642061626f75742073797374656d64206973207768617420796f75206e65656420616674657220746865206c6162'))
print(crypto.decrypt(bytes.fromhex('bb74c7b9634a382df5a22e0b744c6fda63583e0bf0e375a8a5ed1a332b9e0f78aab42a19af61745e4d30c3d04eeee23a7c17fc97d442738ef5fa69ea438b21e1b07fb71b37b52385d0e577c3b0c2da29fb7ae10060aa1f4b486f1d8e27cca8ab7df30af4ad0db52e'),
                     add_data=b''))
'''

#M7
import telnetlib
import json

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

host = "aclabs.ethz.ch"
PORT = 50707
tn = telnetlib.Telnet(host, PORT)

request = {
    'command': 'get_token'
}
json_send(request)
response = json_recv()
token = response['guest token']
ct = bytes.fromhex(token)[:32]
iv = ct[:16]
ct = ct[16:]
tag = bytes.fromhex(token)[32:]
new_iv = bytes([iv[0] ^ 0]) + iv[1:]

#xor the bytes of key such that it is in the enc_key part and these bytes do not interfere with
#the padding, just interfere with the 'guest' string
#maybe just xor first parts of iv?
#do not touch mac_key

response = {'error': 'xd'}
i = 1
bilast = b'\x00' * 32
while 'error' in response:
    bi = i.to_bytes(32)
    xorer = b'\x00' * 24 + bytes([bi[i] ^ bilast[i] for i in range(32)])
    bilast = bi
    i += 1
    request = {
        'command': 'rekey',
        'key': xorer.hex()
    }
    json_send(request)
    response = json_recv()

    request = {
        'command': 'authenticate',
        'token': token
    }
    json_send(request)
    response = json_recv()

request = {
    'command': 'show_state',
    'prefix': ''
}
json_send(request)
response = json_recv()
print(response['resp'])