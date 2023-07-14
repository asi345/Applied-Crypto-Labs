import telnetlib
import json
from datetime import datetime
import re

host = "aclabs.ethz.ch"
PORT = 50406

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

#Copied metadata parser for ease of use
def parse_repr(metadata):
    """Parses a string representation of a Message, returning the metadata fields"""

    majv, minv, src, rcv, ts = re.match(
        r"Montone Protocol \(v(\d+)\.(\d+)\) message from (\d+) to (\d+), sent on (.+)\.",
        metadata,
    ).groups()

    majv = int(majv).to_bytes(2, "little")
    minv = int(minv).to_bytes(1, "little")
    src = int(src).to_bytes(4, "little")
    rcv = int(rcv).to_bytes(4, "little")
    ts = int(datetime.fromisoformat(ts).timestamp()).to_bytes(4, "little")
    return src, rcv, ts, majv, minv

tn = telnetlib.Telnet(host, PORT)

#Asks for challenge and obtains the ciphertext
request = {
    'command': 'flag'
}
json_send(request)
response = json_recv()

m0 = bytes.fromhex(response['m0'])
c0 = bytes.fromhex(response['c0'])
ciphertext = bytes.fromhex(response['ctxt'])

#Gets the metadata from the server to obtain plaintext for metadata
request = {
    'command': 'metadata_leak',
    'm0': m0.hex(),
    'c0': c0.hex(),
    'ctxt': ciphertext.hex()
}
json_send(request)
response = json_recv()
metadata_str = response['metadata']

#Info: Additional meta data is given this time and its size is 35 bytes
#But it is padded, so take it as 48 bytes = 3 blocks.
#Flag is in 'content', however it starts with 100 bytes of known text(6 blocks),
#so flag starts from 7th block of content

#When our ciphertext is decrypted, 1st block must be 'MONTONE-PROTOCOL'
proto_header = b"MONTONE-PROTOCOL"
#We need metadata plaintext because IGE mode xors next block ciphertext with plaintext metadata
sender, receiver, timestamp, major, minor = parse_repr(metadata_str)
#Note that last byte of the block is not provided by server, however we know that additional
#metadata is 3 blocks.
add_meta_len = int(3).to_bytes(1, "little")
metadata = sender + receiver + timestamp + major + minor + add_meta_len

#Initializes the variables for the attack. Note that the attack logic exactly the same as M5,
#it is just repeated with different ciphertext blocks for recovering multiple plaintext
#blocks.
#c0 never changes in a recovery attack
c0_p = c0
#m_prev should be the just previously recovered plaintext block
m_prev = metadata
m_cur = ''
#We put whole thing in 'result'
result = ''
count = 1
#Flag ends with '}'
while '}' not in result:
    #Prepares the next ciphertext components for next plaintext block recovery
    #c1_p = c(i - 1)
    c1_p = ciphertext[16 * count : 16 * (count + 1)]
    #m0_p = m0 xor c1 xor c1_p
    m0_p = xor(xor(m0, ciphertext[0:16]), c1_p)
    #c2_p = m_prev xor p1(proto_header) xor c(i)
    c2_p = xor(xor(m_prev, proto_header), ciphertext[16 * (count + 1) : 16 * (count + 2)])

    #Again, the last byte of the plaintext block is obtained by binary search since metadata
    #sent by server does not include last byte
    left, right = 0, 256
    while right != left:
        mid = (left + right) // 2
        c3_p = b'\x00' * (mid * 16)
        ciphertext_p = c1_p + c2_p + c3_p
        request = {
            'command': 'metadata_leak',
            'm0': m0_p.hex(),
            'c0': c0_p.hex(),
            'ctxt': ciphertext_p.hex()
        }
        json_send(request)
        response = json_recv()
        if 'metadata' in response:
            right = mid
        else:
            left = mid + 1

    #'right' variable holds the last byte of the secret message now
    c3_p = b'\x00' * (right * 16)
    ciphertext_p = c1_p + c2_p + c3_p
    request = {
        'command': 'metadata_leak',
        'm0': m0_p.hex(),
        'c0': c0_p.hex(),
        'ctxt': ciphertext_p.hex()
    }
    json_send(request)
    response = json_recv()
    secret_meta = response['metadata']
    #Parses the obtained metadata so that we extract the plaintext bytes
    pieces = parse_repr(secret_meta)
    #Gets the alphanumeric string of first 15 bytes of the recovered plaintext block
    m_cur = ''.join([piece.decode() for piece in pieces])
    #Last byte comes from our binary search result
    m_cur += chr(right)
    #print(m_cur)
    result += m_cur
    m_prev = m_cur.encode()
    m_cur = ''
    count += 1
print(result)