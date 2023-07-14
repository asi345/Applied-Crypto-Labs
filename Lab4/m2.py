import telnetlib
import json
from Crypto.Random import get_random_bytes

host = "aclabs.ethz.ch"
PORT = 50402

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

#Info: Decryption oracle can return 2 options: a json with a key 'res' or a json with a key 'error'
#Error message means that padding was not correct in our decryption attempt. That means decryption
#oracle can be used as a padding oracle for an attack, just like last question in Lab 3.

#First I get the encrypted flag and initialize the components
request = {
    'command': 'flag',
}
json_send(request)
response = json_recv()
challenge = bytes.fromhex(response['ctxt'])
count = len(challenge) // 16
result = ''
m_prev = bytes.fromhex(response['m0'])
c_prev = bytes.fromhex(response['c0'])

#Decrypt and solve each block one by one, starting from the first block of 'ctxt'. We can not start from
#last block since we need previous plaintext block for correct plaintext recovery in padding oracle attack.
#'m0' gives us this chance for decrypting first block of 'ctxt'. After that we can iterate until the end of
#blocks in 'ctxt' since each time we decrypt and have access to plaintext of previous block.
#Previous ciphertext block is also necessary for decryption in this scheme, so we also utilize 'c0' at first
#iteration and use the previously decrypted ciphertext block of 'ctxt'.
for block in range(0, count):

    #Initalizes required variables for block decryption
    padders = bytes()
    lower = 16 * block
    #Has the form of random bytes of 16 + current ciphertext block to decrypt
    curCipher = get_random_bytes(16) + challenge[lower : lower + 16]
    m_cur = b''

    #For each byte to recover of the plaintext, starting from the last byte to first byte
    for recover in range(1, 17):

        #Prepares the previous ciphertext bytes which corresponds to already decrypted bytes of plaintext
        curPadders = bytes([padder ^ recover for padder in padders])

        #For each byte value to try for padding to be correct
        for trial in range(256):

            cur = curCipher
            #Currently tried out byte for padding
            update = trial ^ cur[-16 - recover]
            #Currently sent ciphertext
            cur = cur[:-16 - recover] + bytes([update]) + curPadders + cur[-16:]
            request = {
                "command": "decrypt",
                "m0": m_prev.hex(),
                "c0": cur[:-16].hex(),
                "ctxt": cur[-16:].hex()
            }
            json_send(request)
            response = json_recv()
            #Means the padding was correct
            if 'res' in response:
                #Represents the plaintext text byte recovered
                found = update ^ recover ^ c_prev[16 - recover]
                #Sets the ciphertext byte to be used in further iterations of decryption
                padders = bytes([update ^ recover]) + padders
                #Byte representation of current plaintext block
                m_cur = bytes([found]) + m_cur
                break
    #Updates the previous blocks since new iteration block will start
    m_prev = m_cur
    c_prev = challenge[lower : lower + 16]
    result += m_cur.decode()
    print(result)

print(result)