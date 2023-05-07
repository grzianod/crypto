import os

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'  # Configuration patch to tell pwntools to not send terminal strings to be printed

from pwn import *
from math import ceil
from Crypto.Cipher import AES

HOST = "130.192.5.212"
PORT = 6541
block_size = 16

if __name__ == '__main__':

    prefix= b"0"*4
    secret = b""
    server = remote(HOST, PORT)
    server.recv(1024)

    for i in range(block_size):
        guess = b'0' * (block_size - (i+1))
        for c in string.printable:
            server.sendline(b"enc")
            tampered = bytes(guess + c.encode() + guess + c.encode())
            print(tampered)
            sleep(.5)
            server.recv(10)
            server.sendline(tampered)
            sleep(.5)
            print(server.recv(1024))

    server.close()
