import telnetlib
import json
from datetime import datetime
import re

host = "aclabs.ethz.ch"
PORT = 50405

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

#Info: 1st block of ciphertext is 'MONTONE-PROTOCOL'
#2nd block of ciphertext is all metadata + additional_metadata_len
#3rd block of ciphertext is what we try to decrypt, secret message is one block
#str(msg) outputs all metadata
#For correct decryption, 1st block must not be touched.
#Change 2nd block with 3rd block so that repr() outputs the secret
#message in a separated way

#This 'change' can not be done directly, IGE mode should be accounted.
#I can not give full details here, but I will try to explain the xor operations needed.

#Asks for challenge and obtains the ciphertext
request = {
    'command': 'init'
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

#When our ciphertext is decrypted, 1st block must be 'MONTONE-PROTOCOL'
proto_header = b"MONTONE-PROTOCOL"
#2nd block of plaintext corresponding to challenge ciphertext is obtained by getting metadata
sender, receiver, timestamp, major, minor = parse_repr(metadata_str)
#Note that last byte of the block is not provided by server, however we know that actually
#secret message is one block exacly and after padding it becomes 2 blocks.
add_meta_len = int(2).to_bytes(1, "little")
metadata = sender + receiver + timestamp + major + minor + add_meta_len

#Constructs the ciphertext that tricks the server and disguises the secret message encryption
#as metadata encryption so that server outputs secret message bytes when it sends metadata
#information.
#Properties of IGE mode is also taken into account and xor operations are made to ensure that
#2nd ciphertext block will correspond to secret message when decrypted. Therefore, server will
#send secret message bytes as metadata.
c0_p = c0
#c1_p = c2 in original ciphertext
c1_p = ciphertext[16:32]
#m0_p = m_0 xor c1 xor c1_p
m0_p = xor(xor(m0, ciphertext[0:16]), c1_p)
#c2_p = p2(metadata) xor p1(proto_header) xor c3
c2_p = xor(xor(metadata, proto_header), ciphertext[32:48])

#The problem is that server does not send last byte of the metadata, so we did not obtain last byte
#of secret message.
#Runs a binary search to precisely determine the last byte of the secret message. This is possible since
#last byte of the secret message actually determines the least number of blocks needed in the ciphertext.
#If too few blocks are provided, error message is obtained. This way, binary search works well to find
#exact boundary to not get error message.
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
pieces = parse_repr(secret_meta)
#Gets the alphanumeric string of first 15 bytes of the secret message
result = ''.join([piece.decode() for piece in pieces])
#Last byte comes from our binary search result
result += chr(right)
#Obtains the flag
request = {
    'command': 'flag',
    'solve': result
}
json_send(request)
response = json_recv()
print(response['flag'])