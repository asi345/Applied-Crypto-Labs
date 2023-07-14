#M0
from Crypto.Hash import MD5, HMAC, SHA256, SHA1
from Crypto.Protocol.KDF import scrypt

PW = '6f6e696f6e732061726520736d656c6c79'
SECRET = '6275742061726520617765736f6d6520f09f988b'
SALT = '696e2061206e69636520736f6666726974746f21'

# Salt is 20 bytes
def onion(pw, salt):
  h = MD5.new()
  h.update(pw)
  h2 = HMAC.new(key=salt, msg=h.digest(), digestmod=SHA1)
  h3 = HMAC.new(key=bytes.fromhex(SECRET), msg=h2.digest(), digestmod=SHA256)
  # Use n = 2**10, r = 32, p = 2, key_len = 64
  h4 = scrypt(h3.digest(), salt, key_len=64, N=2**10, r=32, p=2)
  h5 = HMAC.new(key=salt, msg=h4, digestmod=SHA256)
  return h5.hexdigest()

print(onion(bytes.fromhex(PW), bytes.fromhex(SALT)))

#M1
import telnetlib
import json
from passlib.hash import argon2

host = "aclabs.ethz.ch"
PORT = 50501

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")
'''
tn = telnetlib.Telnet(host, PORT)

request = {
    'command': 'password'
}
json_send(request)
response = json_recv()['res']
password = bytes.fromhex(response)
hp = argon2.hash(password)
request = {
    'command': 'guess',
    'guess': hp
}
json_send(request)
response = json_recv()['res']
print(response)
'''
print('flag{argon_is_a_noble_gas}')

#M3
from string import ascii_lowercase
'''

SALT = bytes.fromhex('b49d3002f2a089b371c3')
HASH = 'd262db83f67a37ff672cf5e1d0dfabc696e805bc'

def find_password():
    for a0 in ascii_lowercase:
        for a1 in ascii_lowercase:
            print(a0 + a1)
            for a2 in ascii_lowercase:
                for a3 in ascii_lowercase:
                    for a4 in ascii_lowercase:
                        for a5 in ascii_lowercase:
                            password = a0 + a1 + a2 + a3 + a4 + a5
                            result = HMAC.new(key=password.encode(), msg=SALT, digestmod=SHA1)
                            if HASH == result.hexdigest():
                                return password
print(find_password())
'''
print('ohnomy')

#M4
'''
PORT = 50504
tn = telnetlib.Telnet(host, PORT)

request = {
    'command': 'salt'
}
json_send(request)
response = json_recv()['salt']
salt = bytes.fromhex(response)

hashes = dict()
for a0 in ascii_lowercase:
    for a1 in ascii_lowercase:
        for a2 in ascii_lowercase:
            for a3 in ascii_lowercase:
                for a4 in ascii_lowercase:
                    password = a0 + a1 + a2 + a3 + a4
                    hashes[HMAC.new(key=salt, msg=password.encode(), digestmod=SHA256).hexdigest()] = password

for i in range(5):
    request = {
        'command': 'password'
    }
    json_send(request)
    h = json_recv()['pw_hash']

    request = {
        'command': 'guess',
        'password': hashes[h]
    }
    json_send(request)
    response = json_recv()
    print(response)

request = {
    'command': 'flag'
}
json_send(request)
response = json_recv()
print(response['flag'])
'''
print('flag{never_look_up_something_you_can_memorise}')

#M5
PORT = 50505
tn = telnetlib.Telnet(host, PORT)

#no pads used
request = {
    'command': 'token'
}
json_send(request)
response = json_recv()
nonce = response['nonce']
enc = bytes.fromhex(response['token_enc'])

collision1 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70')
collision2 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70')
m1 = b"Pepper and lemon spaghetti with basil and pine nuts"
recipe = b"Heat the oil in a large non-stick frying pan. Add the pepper and cook for 5 mins. Meanwhile, cook the pasta for 10-12 mins until tender. Add the courgette and garlic to the pepper and cook, stirring very frequently, for 10-15 mins until the courgette is really soft. Stir in the lemon zest and juice, basil and spaghetti (reserve some pasta water) and toss together, adding a little of the pasta water until nicely coated. Add the pine nuts, then spoon into bowls and serve topped with the parmesan, if using. Taken from [www.bbcgoodfood.com/recipes/pepper-lemon-spaghetti-basil-pine-nuts]"
token = b"username:admin&m1:" + m1 + b"&fav_food_recipe:" + recipe

replace = b"username:admin&m1:" + collision1 + b"&fav_food_recipe:" + b"A" * (len(recipe) - len(collision1) + len(m1))
new_token = bytes([token[i] ^ replace[i] ^ enc[i] for i in range(len(token))])

request = {
    'command': 'login',
    'nonce': nonce,
    'token_enc': new_token.hex(),
    'm2': collision2.hex()
}
json_send(request)
response = json_recv()

request = {
    'command': 'flag'
}
json_send(request)
response = json_recv()
print(response['res'])