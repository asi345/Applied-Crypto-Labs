import telnetlib
import json

host = "aclabs.ethz.ch"
PORT = 50401

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

#The token is compromised of key value pairs of username, role and favourite_coffee,
#all divided by a '&' character.
#Also, when logging in, if a duplicate of a key is encountered, server discards the new
#duplicate. This means that I have to give the 'role' key and 'admin' value before it
#occurs in the token. Only chance is concatenating it in the username.
#Therefore, username is injected a '&' with a 'role-=admin' key value so that when logged in,
#the parser will parse role as admin at first.
request = {
    'command': 'register',
    'username': 'ata&role=admin',
    'favourite_coffee': 'latte'
}
json_send(request)
response = json_recv()
token = response['token']

request = {
    'command': 'login',
    'token': token
}
json_send(request)
response = json_recv()
print(response['res'])

#Next step is changing 'good_coffee' to 'true' by 'change_settings' command. We are admin now.
request = {
    'command': 'change_settings',
    'good_coffee': 'true'
}
json_send(request)
response = json_recv()
print(response['res'])

#Now we can get the flag.
request = {
    'command': 'get_coffee'
}
json_send(request)
response = json_recv()
print(response['res'])