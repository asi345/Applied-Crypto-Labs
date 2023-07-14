#M4
import telnetlib
import json
from math import ceil
from Crypto.Hash import SHAKE256

host = 'aclabs.ethz.ch'
PORT = 51004

#Remote server communication functions
def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

#XOR function for ease of implementation
def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b), f"{len(a)}, {len(b)}"
    return bytes(x ^ y for x, y in zip(a, b))

#Functions given in the handout
def ceil2(a: int, b: int) -> int:
    # Necessary because of floating point precision loss
    return a // b + (1 if a % b != 0 else 0)

def get_multiplier(m_max: int, m_min: int, N: int, B: int) -> int:
    tmp = ceil2(2 * B, m_max - m_min)
    r = tmp * m_min // N
    alpha = ceil2(r * N, m_min)
    return alpha, r

tn = telnetlib.Telnet(host, PORT)

#Get public key parameters
request = {
    'command': 'get_params'
}
json_send(request)
response = json_recv()
N = int(response['N'])
e = int(response['e'])

#B as described in the handout
B = 2**(1024 - 8)
#If the flag is found up to now
#This variable is used to help when my solution can not come up with a valid flag
#It just gets a different ciphertext from server since it is randomized
#I believe my solution will run at most 2 or 3 times since it can find the flag around %80 of the time in the first try
is_found = False

while not is_found:
    #Get encrypted flag
    request = {
        'command': 'flag'
    }
    json_send(request)
    response = json_recv()
    c = int.from_bytes(bytes.fromhex(response['flag']))

    #Step 2: Improving the bounds
    #Learn alpha_0 by trying out values starting from 256(2**8)
    #Since we know that last 8 bits are 0 in original m, we need to multiply m with numbers bigger from 2**8
    alpha_0 = 256
    while True:
        #cur_c = alpha_0^e * m^e mod N
        cur_c = (pow(alpha_0, e, N) * c) % N
        request = {
            'command': 'decrypt',
            'ctxt': cur_c.to_bytes(128, 'big').hex() #128 bytes = 1024 bits
        }
        json_send(request)
        response = json_recv()
        #Check if first padding check has passes, meaning that for the first time we see alpha_0 * m > N
        #It also works on the observation that alpha_0 * m < N + B, since we know
        #(alpha_0 - 1) * m < N and m < B implies that alpha_0 * m < N + B
        if 'error' not in response or 'Error: Decryption failed' not in response['error']:
            break
        alpha_0 += 1

    #Set first improved boundaries: N < alpha_0 * m < N + B -> ceil(N / alpha_0) <= m < ceil((N + B) / alpha_0)
    #The reasoning for these boundaries are explained above
    m_min = ceil(N / alpha_0)
    m_max = ceil((N + B) / alpha_0)

    #While loop triggers until we have small range of m values left, we can check them one by one in a small amount of time
    #I am not waiting until m_max - m_min = 1, because I noticed that the boundary is not always converging to one unique value,
    #but rather stops at a small range of values, which was always less that 5
    while m_max - m_min > 5:
        #Get multiplier alpha
        #I also added r into the output for the precise computation of (r * N + B) / alpha
        alpha, r = get_multiplier(m_max, m_min, N, B)
        #Now we have the form of B-point:
        #For a r in Z, r * N <= alpha * m_min < B + r * N <= alpha * m_max <= (r + 1) * N
        #We can use this knowledge as follows:
        #We calculate alpha^e * m^e mod N and send it to decrypt at the server
        #Server will obtain alpha * m mod N and will try to decrypt it

        #The first padding check will fail if alpha * m mod N has not 8 leading 0 bits, meaning that alpha * m mod N >= B
        #This means that for possible values of m we have in range, 'alpha * m mod N >= B' statement must hold for all of them
        #Therefore, we can eliminate the cases where 'alpha * m_min < B + r * N'
        #This elimination will result in setting alpha * m_min = B + r * N, therefore new m_min = (r * N + B) // alpha

        #Similar argument holds for m_max too
        #If the first padding check will pass, then we have alpha * m mod N < B
        #This means that for possible values of m we have in range, 'alpha * m mod N < B' statement must hold for all of them
        #Therefore, we can eliminate the cases where 'alpha * m_max >= B + (r + 1) * N'
        #This elimination will result in setting alpha * m_max = B + r * N, therefore new m_max = (r * N + B) // alpha

        #As a result of this elimination in the boundaries, we roughly eliminate half of the possible values of m
        #That is why the algorithm works in a binary search fashion

        #Check if alpha^e * m^e mod N passes first padding check
        #In other words, check if alpha * m mod N has 8 leading 0 bits
        alpha_m = pow(alpha, e, N) * c % N
        request = {
            'command': 'decrypt',
            'ctxt': alpha_m.to_bytes(128, 'big').hex()
        }
        json_send(request)
        response = json_recv()
        #If first padding check fails(first byte is not 0x00), then we update m_min to be (r * N + B) // alpha
        if 'error' in response and 'Error: Decryption failed' in response['error']:
            m_min = (r * N + B) // alpha
        else: #If first padding check passes(first byte is 0x00), then we update m_max to be (r * N + B) // alpha
            m_max = (r * N + B) // alpha

    #Use the already implemented unpadder from server code to retrieve plaintext(flag) for each possible m value left in the range
    #We print every possibility, but since there are only 6 sequential values at maximum, they can only differ in their last 2 bytes
    #Therefore, we can easily find the correct flag by looking at the last bytes of the printed plaintexts, where we should
    #observe '}' character
    RSA_KEYLEN = 1024
    RAND_LEN = 256
    P_LEN = (RSA_KEYLEN - RAND_LEN - 8) // 8
    #Use the unpadder for each possible m value
    for m in range(m_min, m_max + 1):
        m = m.to_bytes(RSA_KEYLEN // 8, 'big')

        rand = m[1:1+RAND_LEN//8]
        ptxt_masked = m[1+RAND_LEN//8:]
        rand_hashed = SHAKE256.new(rand).read(P_LEN)
        ptxt_padded = xor(ptxt_masked, rand_hashed)

        for i, b in enumerate(ptxt_padded):
            if b == 1 and all(ch == 0 for ch in ptxt_padded[:i]):
                res = ptxt_padded[i+1:]
                try:
                    print(res.decode())
                    is_found = True
                except:
                    pass
                break