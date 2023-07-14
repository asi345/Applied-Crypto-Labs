import telnetlib
import json

host = "aclabs.ethz.ch"
PORT = 50403

#Remote server communication functions
def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

#Xor just for ease of use
def xor(a: bytes, b: bytes):
    return bytes(x ^ y for x, y in zip(a, b))

tn = telnetlib.Telnet(host, PORT)

#Info: CBC mode is used, but it decrypts the messages instead of encrypting
#This makes that each ciphertext block is xored with previous plaintext block
#If we know the previous plaintext block we can calculate the result of block
#cipher decryption(without CBC mode).

#Need 3 bytes for a block to fill, it becomes 32 bytes and result is 3 blocks(1 of them is padding)

count = 0
#10 solves are needed
while count < 10:
    #Since space is just one byte, we will try each byte value as secret byte and check the result
    for trial in range(256):
        curByte = bytes([trial])
        #We inject whole 2 new block in the message, but the format is the same as the way the server
        #creates the plaintext blocks. This allows us to create 5 plaintext blocks with last of them
        #being the padding.
        request = {
            'command': 'encrypt',
            'file_name': 'xd',
            'data': (b'0&secret_byte=' + curByte + b'filename=xd&data=0').hex()
        }
        json_send(request)
        response = json_recv()
        ctxthex = response['ctxt']        
        #First and third plaintext blocks will be the same and we do not care about them so much.
        #Second plaintext block will have our trial of secret byte as the last byte of the plaintext block.
        #Fourth plaintext block will have the original secret byte as the last byte of the plaintext block.
        #If second and fourth plaintext block is the same, then our trial is the secret byte.
        #Note that just comparing second and fourth block is sufficient since first and third block is the
        #same so xoring operation will not change the equality.
        if ctxthex[32:64] == ctxthex[96:128]:
            request = {
                'command': 'solve',
                'solve': curByte.hex()
            }
            json_send(request)
            response = json_recv()
            print(response['res'], trial)
            break
    count += 1
request = {
    'command': 'flag'
}
json_send(request)
response = json_recv()
print(response['flag'])