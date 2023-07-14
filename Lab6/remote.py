#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

tn = telnetlib.Telnet("aclabs.ethz.ch", 50690)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

json_send({
    "command": "hashpump",
    "mac": "05c31528cf681267c35625fc682d8039ff190519b5e349eb07cbb644990987c9",
    "data": "asdf",
    "append": "hjkl",
})

print(json_recv())
