#M0
import telnetlib
import json

'''
def readline(tn):
    return tn.read_until(b"\n")

def json_recv(tn):
    line = readline(tn)
    return json.loads(line.decode())

def json_send(tn, req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

host2 = "aclabs.ethz.ch"
host = 'localhost'
PORT = 50600

tn = telnetlib.Telnet(host2, PORT)

request = {
    'command': 'token'
}
json_send(tn, request)
response = json_recv(tn)
token = response['token']
print('token', token)

tn2 = telnetlib.Telnet(host2, 50690)
json_send(tn2, {
    "command": "hashpump",
    "mac": token['mac'],
    "data": bytes.fromhex(token['command_string']).decode(),
    "append": "&command=flag",
})
response = json_recv(tn2)
print(bytes.fromhex(response['new_data']))

token['command_string'] = response['new_data']
token['mac'] = response['new_hash']
print(token)


request = {
    'command': 'token_command',
    'token': token
}
json_send(tn, request)
response = json_recv(tn)
print(response)
'''
print('flag{b0p_1t_tw1st_1t_pump_1t}')

#M2

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

'''
from shazam import SHAzam

host = "aclabs.ethz.ch"
#host = 'localhost'
PORT = 50602

tn = telnetlib.Telnet(host, PORT)

request = {
    'command': 'get_token'
}
json_send(request)
token = json_recv()
comm = b'\x00' * 16 + bytes.fromhex(token['authenticated_command'])

BLOCK_SIZE_BYTES = 64
len2 = len(comm) * 8
padder = comm + b'\x80' + b'\x00' * ((BLOCK_SIZE_BYTES - len(comm) - 9) % BLOCK_SIZE_BYTES) + (len2.to_bytes(8, 'big'))
print(comm)
print(padder, len(padder))

padder += b'&command=flag'

sh = SHAzam()
sh.leftoff(padder, token['mac'])
print(sh.buffer, sh.length, sh.hash)
#sh.update(b'&command=flag')
print(sh.buffer, sh.length, sh.hash)
#padder += b'&command=flag'
padder = padder[16:]
print(padder)

request = {
    'command': 'authenticated_command',
    'authenticated_command': padder.hex(),
    'mac': sh.digest().hex()
}
json_send(request)
response = json_recv()
print(response)
'''
print('flag{n0w_1_just_w4lk_thr0ugh_th3_w4llz}')

#M3
'''
from string import ascii_letters, digits
from Crypto.Hash import HMAC, SHA256
ALPHABET = ascii_letters + digits

host = "aclabs.ethz.ch"
PORT = 50603

tn = telnetlib.Telnet(host, PORT)

request = {
    'command': 'corrupt'
}
json_send(request)
k_auth = json_recv()['res'][54:]
k_auth = bytes.fromhex(k_auth)

tags = {}
for a0 in ALPHABET:
    print(a0)
    for a1 in ALPHABET:
        for a2 in ALPHABET:
            for a3 in ALPHABET:
                plain = a0 + a1 + a2 + a3
                tags[HMAC.new(k_auth, plain.encode(), SHA256).digest().hex()] = plain

for i in range(128):
    request = {
        'command': 'challenge'
    }
    json_send(request)
    ciphertext = json_recv()['res']
    plain = tags[ciphertext[64:]]

    request = {
        'command': 'guess',
        'guess': plain
    }
    json_send(request)
    response = json_recv()['res']
    print(response)
request = {
    'command': 'flag'
}
json_send(request)
response = json_recv()['res']
print(response)
'''
print('flag{hmac_1s_det3rmin1stic_indcpa_secur1ty_of_encrypt_and_mac_h4s_g0ne}')

#M4
host = "aclabs.ethz.ch"
PORT = 50604

tn = telnetlib.Telnet(host, PORT)

request = {
    'command': 'flag'
}
json_send(request)
cflag = json_recv()

count = len(cflag['ctxt']) // 2
result = ''

for i in range(count):
    for trial in range(256):
        try:
            request = {
                'command': 'encrypt',
                'ptxt': result + bytes([trial]).decode()
            }
            json_send(request)
            response = json_recv()

            request = {
                'command': 'decrypt',
                'nonce': cflag['nonce'],
                'ctxt': cflag['ctxt'][:2 * (i + 1)],
                'mac_tag': response['mac_tag']
            }
            json_send(request)
            response = json_recv()
            if response['success']:
                result += chr(trial)
                print(result)
                break
        except:
            continue
print(result)
print('flag{encrypt_4nd_m4c_is_v3ry_f14wed}')