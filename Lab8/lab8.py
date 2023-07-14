#M0
import telnetlib
import json
import rsa
from Crypto.Util import number

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")
'''
host = "aclabs.ethz.ch"
PORT = 50800
tn = telnetlib.Telnet(host, PORT)

pk, sk, primes = rsa.rsa_key_gen()
N, e = pk
N, d = sk
p, q = primes

request = {
    'command': 'set_parameters',
    'N': N,
    'e': e,
    'd': d,
    'p': p,
    'q': q
}
json_send(request)
response = json_recv()

request = {
    'command': 'encrypted_flag'
}
json_send(request)
response = json_recv()

c = int(response['res'][49:])
m = rsa.rsa_dec((N, d), c)
print(m.to_bytes(75))
'''
print('flag{d0_not_under_4ny_c1rcumstances_us3_textb00k_rsa}')

#M1
'''
host = "aclabs.ethz.ch"
PORT = 50801
tn = telnetlib.Telnet(host, PORT)

request = {
    'command': 'encrypted_flag'
}
json_send(request)
response = json_recv()
c = int(response['encypted_flag'], 16)
N = int(response['N'], 16)
e = int(response['e'], 16)

mult = pow(2, e, N)
c2 = (mult * c) % N
request = {
    'command': 'decrypt',
    'ciphertext': hex(c2)[2:]
}
json_send(request)
response = json_recv()
f2 = int(response['res'], 16)
f = f2 // 2
f = number.long_to_bytes(f)
print(f.decode())
'''
print('flag{1_s41d_0o0oh_1m_bl1nd3d_RSA}')

#M2
'''
from numpy import cbrt
host = "aclabs.ethz.ch"
PORT = 50802
tn = telnetlib.Telnet(host, PORT)

request = {
    'command': 'encrypted_flag'
}
json_send(request)
response = json_recv()
print(response)
N = int(response['N'])
e = int(response['e'])
c = int(response['ctxt'])
'''
def find_invpow(x,n):
    """Finds the integer component of the n'th root of x,
    an integer such that y ** n <= x < (y + 1) ** n.
    """
    high = 1
    while high ** n < x:
        high *= 2
    low = high // 2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1
'''
f = find_invpow(c, 3)
f = number.long_to_bytes(f)
print(f.decode())
'''
print('flag{pour_one_for_the_short_kings}')

#M3
'''
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
host = "aclabs.ethz.ch"
PORT = 50803
tn = telnetlib.Telnet(host, PORT)

request = {
    'command': 'encrypted_flag'
}
json_send(request)
response = json_recv()

N = int(response['N'])
e = int(response['e'])
c = bytes.fromhex(response['ctxt'])
'''
def sqrter(n):
    r = 1 << ((n.bit_length() + 1) >> 1)
    while True:
        newr = (r + n // r) >> 1  # next estimate by Newton-Raphson
        if newr >= r:
            return r
        r = newr
'''
p = sqrter(N)
q = p + 2
diff = p * q - N
diffs = sqrter(diff)
p -= diffs
q += diffs
count = 0
while p * q != N:
    p -= 2
    q += 2
    if count == 5:
        break
    count += 1

phi = (p - 1) * (q - 1)
d = number.inverse(e, phi)
key = RSA.construct((N, e, d))
cipher = PKCS1_OAEP.new(key)
f = cipher.decrypt(c)
print(f.decode())
'''
print('flag{cu1us_r31_d3m0nstr4t10n3m_m1r4b1l3m_s4n3_d3t3x1_h4nc_m4rg1n1s_3x1gu1t4s_n0n_c4p3r3t}')

#M4
'''
from server4.phonebook import phonebook
from sympy.ntheory.modular import crt
host = "aclabs.ethz.ch"
PORT = 50804
tn = telnetlib.Telnet(host, PORT)

cs, Ns = [], []

for invitee in phonebook:
    request = {
        'command': 'invite',
        'invitee': invitee
    }
    json_send(request)
    response = json_recv()

    cs.append(int(response['ciphertext'], 16))
    Ns.append(int(phonebook[invitee]['N']))

#Find m^3 with Chinese Remainder Theorem
m3 = crt(Ns, cs)[0]
f = find_invpow(m3, 3)
f = number.long_to_bytes(f)
print(f.decode())
'''
print("Hi! I'd like to invite you to my birthday party! You must know the secret password, which by the way is flag{wh4t_4_p4rty_p00p3r}. Come with a costume: the theme is cryptographic horror! I've heard someone is going to dress up as textbook RSA! xoxo ~Kien")

#M5
'''
host = "aclabs.ethz.ch"
PORT = 50805
tn = telnetlib.Telnet(host, PORT)
'''
def eea(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = eea(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y
'''
request = {
    'command': 'pub_key'
}
json_send(request)
response = json_recv()

N = int(response['N'], 16)

e1 = 1
response = {'error': 'xd'}

while 'error' in response:
    e1 += 2
    request = {
        'command': 'encrypt',
        'e': e1
    }
    json_send(request)
    response = json_recv()

c1 = int(response['ciphertext'], 16)
e2 = e1
response = {'error': 'xd'}

while 'error' in response:
    e2 += 2
    request = {
        'command': 'encrypt',
        'e': e2
    }
    json_send(request)
    response = json_recv()

c2 = int(response['ciphertext'], 16)
gcd, x, y = eea(e1, e2)
part1 = pow(c1, x, N)
part2 = pow(c2, y, N)
f = (part1 * part2) % N
f = number.long_to_bytes(f)
print(f.decode())
'''
print('flag{y34h_s0_th1s_fl4g_1s_pr3tty_l0ng_0th3rw1s3_0n3_c0uld_just_d0_4_cub3_r00t_wh1ch_w0uld_suck}')

#M5
'''
from math import gcd
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
host = "aclabs.ethz.ch"
PORT = 50806
tn = telnetlib.Telnet(host, PORT)

Ns = []
#Mining your p’s and q’s, slide 28 of Lecture 22

def coll(N_new):
    for ind, N in enumerate(Ns):
        g = gcd(N, N_new)
        if g != 1:
            return g, ind
    return False

request = {
    'command': 'generate'
}
json_send(request)
response = json_recv()

N_new = int(response['N'])
res = coll(N_new)
while not res:
    Ns.append(N_new)
    request = {
        'command': 'generate'
    }
    json_send(request)
    response = json_recv()
    N_new = int(response['N'])
    res = coll(N_new)

e = 65537
p, ind = res
N = Ns[ind]
q = N // p
phi = (p - 1) * (q - 1)
d = number.inverse(e, phi)
key = RSA.construct((N, e, d))
cipher = PKCS1_OAEP.new(key)

request = {
    'command': 'encrypt',
    'index': ind
}
json_send(request)
response = json_recv()

c = bytes.fromhex(response['encrypted_flag'])
f = cipher.decrypt(c)
print(f.decode())
'''
print('flag{3_plur1bus_unum}')