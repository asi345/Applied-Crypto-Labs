import telnetlib
import json

host = "aclabs.ethz.ch"
PORT = 50404

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

#Initializes the variables that is updated with each recovered byte of the flag
count = 0
result = b'~'
#Last character of the flag is always '}'
last = b'}'[0]

#Loops until reaching end of the flag, recovers one byte of the flag at each iteration
while result[-1] != last:

    #Info: The constructed plaintext of the server is 21 bytes without any of our input
    #For first byte , need 10 bytes to fill, 1 byte with data, 9 with filename
    #9 8 7 .. 1 0 15
    #0 1 2 .. 8 9 10
    #Filename is constructed such that the current byte to recover from flag is always at
    #the last byte of the plaintext/ciphertext block.
    #Data field will always be '0'
    filename = 'x' * ((9 - count) % 16)

    #Tries all bytes as the current byte of the flag
    for trial in range(256):
        curByte = bytes([trial])
        #'data' is field is constructed such that it will cause the plaintext in the server to be
        #filename={filename}&data=0&flag={previosly recovered bytes of the flag}||{trial}filename={filename}&data=0&flag={original flag in the server}
        #This construction also ensures that 'trial' is the last byte of a block and currently
        #flag byte to be recovered is the last byte of the last byte of another block
        request = {
            'command': 'encrypt',
            'file_name': filename,
            'data': (b'0&flag=' + result[1:] + curByte + b'filename=' + filename.encode() + b'&data=0').hex()
        }
        json_send(request)
        response = json_recv()
        ctxthex = response['ctxt']        

        #If base = 1, then last byte of the 2nd block is trial and last byte of the 4th block is the current flag byte to recover
        #If base = 2, then they are 3rd and 6th blocks
        #If base = 3, then they are 4th and 8th blocks
        #...
        base = (count + 6) // 16 + 1
        #Even if CBC mode is used, since the previous blocks of the blocks which contain our trial as last byte and
        #currently recovered byte of the flag as the last byte, these 2 blocks will have the same ciphertext for
        #a value of the trial.
        if ctxthex[base * 32:base * 32 + 32] == ctxthex[(base + 1) * 64 - 32:(base + 1) * 64]:
            #Stores the byte in 'result'
            result += curByte
            #print(result[1:].decode())
            break
    count += 1
#First byte of the result was dummy
print(result[1:].decode())