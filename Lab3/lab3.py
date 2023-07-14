#A0
import telnetlib
import json
REMOTE = True
PORT = 50390
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

'''
request = {
    "command": "hex_command",
    "hex_command": "ab"
}
json_send(request)
response = json_recv()
print(response)
'''
print('flag{CongratsExceptionalWork}')

#M1
#SAME NONCE USED FOR EACH ENCRYPTION, JUST TAKE DIFF OF INTRO+PAD AND FLAG+PAD TO ACHIEVE ENCRYPTED FLAG STRING
'''
PORT = 50301
tn = telnetlib.Telnet(host, PORT)
request = {
    "command": "howto"
}
json_send(request)
response = json_recv()
enc_intro = bytes.fromhex(response['res'][-32:])

#we have enc of intro\x11..
#we need enc of flag\x12..
initial = b'intro' + b'\x0b' * 11
target = b'flag' + b'\x0c' * 12
diff = bytes([initial[i] ^ target[i] for i in range(16)])
enc_flag = bytes([diff[i] ^ enc_intro[i] for i in range(16)])

request = {
    "command": "encrypted_command",
    "encrypted_command": enc_flag.hex()
}
json_send(request)
response = json_recv()
print(response)
'''
print('flag{https://ee.stanford.edu/~hellman/publications/24.pdf}')

#M2
#JUST ACHIEVE DECRYPTING ONE TEXT, THAT WILL BE VALID DECRYPTION, THAN AGAIN USE THE SAME LOGIC AS ABOVE
#TAKE DIFF AND SEND. SINCE CTR IS FIXED FOR EACH MESSAGE FOR ONE RUN
'''
PORT = 50302
tn = telnetlib.Telnet(host, PORT)

isDec = False
integer = 0
while not isDec:
    dump = integer.to_bytes(16).hex()
    request = {
        "command": "encrypted_command",
        "encrypted_command": dump
    }
    json_send(request)
    response = json_recv()
    if "Failed" not in response['res']:
        isDec = True
    integer += 1
integer -= 1
found = bytes.fromhex(response['res'][17:])
needed_pad = 16 - len(found)
found += needed_pad.to_bytes() * needed_pad
initial = integer.to_bytes(16)
target = b'flag' + b'\x0c' * 12
diff = bytes([initial[i] ^ target[i] for i in range(16)])
enc_flag = bytes([diff[i] ^ found[i] for i in range(16)])
request = {
    "command": "encrypted_command",
    "encrypted_command": enc_flag.hex()
}
json_send(request)
response = json_recv()
print(response)
'''
print("flag{CTRintuitive, isn't it?}")

#M3
#CIPHERTEXT IS IV||C1, SO USING ENCRYPTION OF intro\x11\x12.., DO BIT FLIPS IN IV SUCH THAT
#THESE BIT FLIPS WILL MAKE C1 DECRYPT TO flag\x12\x12..
'''
PORT = 50303
tn = telnetlib.Telnet(host, PORT)

request = {
    "command": "howto"
}
json_send(request)
response = json_recv()
iv = bytes.fromhex(response['res'][-64:-32])
enc_intro = response['res'][-32:]

initial = b'intro' + b'\x0b' * 11
target = b'flag' + b'\x0c' * 12
diff = bytes([initial[i] ^ target[i] for i in range(16)])
iv_for_flag = bytes([diff[i] ^ iv[i] for i in range(16)])
request = {
    "command": "encrypted_command",
    "encrypted_command": iv_for_flag.hex() + enc_intro
}
json_send(request)
response = json_recv()
print(response)
'''
print('flag{MalleableBlockChaining}')

#M4.0
'''
PORT = 50340
tn = telnetlib.Telnet(host, PORT)

integer = 0
while integer < 300:
    dump = integer.to_bytes(16).hex()
    request = {
        "command": "decrypt",
        "ciphertext": dump
    }
    json_send(request)
    response = json_recv()

    if len(response['res']) != 160:
        request = {
            "command": "guess",
            "guess": False
        }
    else:
        request = {
            "command": "guess",
            "guess": True
        }
    json_send(request)
    response = json_recv()
    print(response)
    integer += 1

request = {
    "command": "flag"
}
json_send(request)
response = json_recv()
print(response['res'])
'''
print('flag{WelcomeToDelphi}')

#M4.1
'''
PORT = 50341
tn = telnetlib.Telnet(host, PORT)

integer = 0
while integer < 100:
    request = {
        "command": "challenge"
    }
    json_send(request)
    challenge = json_recv()['res']

    for trial in range(256):

        cur = bytes.fromhex(challenge)
        update = trial ^ cur[-17]
        cur = cur[:-17] + bytes([update]) + cur[-16:]
        request = {
            "command": "decrypt",
            "ciphertext": cur.hex()
        }
        json_send(request)
        response = json_recv()

        if len(response['res']) != 128:
            #last byte is \x01
            request = {
                "command": "guess",
                "guess": chr(trial ^ 1)
            }
            json_send(request)
            response = json_recv()
            print(response['res'], trial)
            break
    
    integer += 1

request = {
    "command": "flag"
}
json_send(request)
response = json_recv()
print(response['res'])
'''
print('flag{ASpectreIsHauntingCrypto}')

#M4.2
'''
PORT = 50342
tn = telnetlib.Telnet(host, PORT)

integer = 0
while integer < 10:
    request = {
        "command": "challenge"
    }
    json_send(request)
    challenge = bytes.fromhex(json_recv()['res'])
    guess = ''
    padders = bytes()

    for recover in range(1, 17):

        curPadders = bytes([padder ^ recover for padder in padders])

        for trial in range(256):

            cur = challenge
            update = trial ^ cur[-16 - recover]
            cur = cur[:-16 - recover] + bytes([update]) + curPadders + cur[-16:]
            request = {
                "command": "decrypt",
                "ciphertext": cur.hex()
            }
            json_send(request)
            response = json_recv()

            if len(response['res']) != 128:
                #last bytes are x numbers to pad
                found = trial ^ recover
                #vay amk ya kac saat verdim su satir icin
                padders = bytes([update ^ recover]) + padders
                guess = chr(found) + guess
                print(guess)
                break
    
    request = {
        "command": "guess",
        "guess": guess
    }
    json_send(request)
    response = json_recv()
    print(response['res'])

    integer += 1

request = {
    "command": "flag"
}
json_send(request)
response = json_recv()
print(response['res'])
'''
print('flag{TheSpectreOfINDCCASecurity}')

#M4.3
#WHEN DECRYPTION IS SUCCESSFUL EVEN IF MEANINGLESS IN ENGLISH, THE ENCRYPTED RECEIVED MESSAGE CONTAINS
#FLAG
#response length: 128 -> can not unpad, 192 -> can not decode bytes
#128 0  256 151 224 153 288 380 just for reference
'''
from Crypto.Random import get_random_bytes

PORT = 50343
tn = telnetlib.Telnet(host, PORT)

dump = get_random_bytes(16).hex()
request = {
    "command": "encrypted_command",
    "encrypted_command": dump
}
json_send(request)
response = json_recv()
result = response['res']

request = {
    "command": "encrypted_command",
    "encrypted_command": result
}
json_send(request)
response = json_recv()
#Bu mesaj flagli olan olmali
result = response['res']

challenge = bytes.fromhex(result)
count = len(challenge) // 16
result = ''

for block in range(1, count):

    padders = bytes()
    lower = 16 * (count - block)
    curCipher = get_random_bytes(16) + challenge[lower : lower + 16]

    for recover in range(1, 17):

        curPadders = bytes([padder ^ recover for padder in padders])

        for trial in range(256):

            cur = curCipher
            update = trial ^ cur[-16 - recover]
            cur = cur[:-16 - recover] + bytes([update]) + curPadders + cur[-16:]
            request = {
                "command": "encrypted_command",
                "encrypted_command": cur.hex()
            }
            json_send(request)
            response = json_recv()

            length = len(response['res'])
            if length != 128:
                #last bytes are x numbers to pad
                found = update ^ challenge[lower - recover] ^ recover
                #vay amk ya kac saat verdim su satir icin
                padders = bytes([update ^ recover]) + padders
                result = chr(found) + result
                #print(result, len(response['res']), trial)
                break
'''
print('flag{You did not expect the flag to span a single block, did you?}')