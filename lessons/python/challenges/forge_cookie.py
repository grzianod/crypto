import base64
import json
import os

from Crypto.Random import get_random_bytes

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'  # Configuration patch to tell pwntools to not send terminal strings to be printed

from pwn import *
from math import ceil
from Crypto.Cipher import AES

HOST = "130.192.5.212"
PORT = 6521

if __name__ == '__main__':
    name = ", admin"
    token = json.dumps({
        "username": name
    })
    print(token)
    tamp = bytearray(token.encode())
    tamp[13] = 30
    print(tamp)

    server = remote(HOST, PORT)
    server.recvline()
    server.sendafter(b"> ", name + "\n")
    print(server.recvline().decode())
    output = server.recvline().decode()

    nonce = base64.b64decode(output[20:36]).hex().encode()
    token = base64.b64decode(output[37:]).hex().encode()

    tamp_token = bytearray(token.decode())
    for i in range(128):
        tamp_token[26] = i.to_bytes(1, byteorder="big")
        server.recvline()
        server.recvline()
        server.recvline()
        server.recvline()
        server.sendafter(b"> ", b"flag\n")
        server.recvline()
        server.sendafter(b"> ", tamp_token.hex().encode() + b"\n")



    print(nonce)
    print(token)