#M3
import telnetlib
import json

host = 'aclabs.ethz.ch'
PORT = 51003

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

#Info: We only need to get how many leading 0 bits are there in the beginning of m
#Note that if m^e mod N is a valid ciphertext, then 2^e * m^e mod N is also a valid ciphertext
#Also when decrypted, 2^e * m^e mod N produces the plaintext 2 * m mod N before padding removal
#In addition, notice that 2 * m mod N is just m shifted left by 1 bit

#If now we observe a Check 1 error("Error: Decryption failed"), which means first leading byte
#is not 0x00, then we know our shifting has broken the padding rule that first byte must be 0x00
#This means that previously we only had 8 bits of 0 at the start of the m!

#We can increasingly shift m by 1 bit until we encounter Check 1 error, then when we see it we can
#add 8 to how many bits we have shifted and this gives the number of leading 0 bits
#To find i, we can just subtract it from 1024(max bit length) to get 'i'

#Get public key parameter e and N
request = {
    'command': 'get_params'
}
json_send(request)
response = json_recv()
N = int(response['N'])
e = int(response['e'])

#Cache 2^e mod N for faster computation time
mult2 = pow(2, e, N)

#We need to solve 256 challenges
for count in range(256):
    #Get challenge
    request = {
        'command': 'get_challenge'
    }
    json_send(request)
    response = json_recv()
    c = int.from_bytes(bytes.fromhex(response['challenge']))
    cur_c = c
    #How many shifts we did in this challenge
    shift = 0
    while True:
        #Shift c by 1 bit
        cur_c = (mult2 * cur_c) % N
        request = {
            'command': 'decrypt',
            'ctxt': cur_c.to_bytes(128, 'big').hex()
        }
        json_send(request)
        response = json_recv()
        #Check if leading byte is 0x00 or not
        if 'error' in response and 'Error: Decryption failed' in response['error']:
            break
        shift += 1
    #We have shifted by 'shift' bits, so we have 1024 - 8 - shift bits to represent the plaintext
    nonzero = 1024 - 8 - shift
    #Send solution
    request = {
        'command': 'solve',
        'i': nonzero
    }
    json_send(request)
    response = json_recv()

#Get flag
request = {
    'command': 'flag'
}
json_send(request)
response = json_recv()
print(response['flag'])