import os

from Crypto.Util.Padding import pad

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'  # Configuration patch to tell pwntools to not send terminal strings to be printed

from pwn import *
from math import ceil
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long

HOST = "130.192.5.212"
PORT = 6552


def print_format(output):
    for z in range(len(output)):
        if z % 32 == 0:
            print(" " + str(ceil(z / 32)), end=": ")
        print(output[z:z + 1], end="")
    print("\n")
    return


if __name__ == '__main__':
    username = "0000000" + pad(b'true', AES.block_size).decode() + "000000000"

    server = remote(HOST, PORT)
    server.sendafter(b"Username: ", username.encode() + b"\n")
    output = long_to_bytes(int(server.recvline().decode())).hex().encode()
    print(output)
    tampered = output[0:32] + output[96:128] + output[64:96] + output[32:64]
    print(tampered)
    output = bytes_to_long(tampered)
    server.recvline()
    server.recvline()
    server.recvline()
    server.recvline()
    server.sendafter(b"> ", b"flag\n")

    server.sendafter(b"Cookie: ", str(output).encode() + b"\n")
    print(server.recvline().decode())
