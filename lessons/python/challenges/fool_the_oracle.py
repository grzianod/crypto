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

    print(AES.block_size)
    secret = b""
    server = remote(HOST, PORT)
    server.recvline()
    server.recvline()
    server.recvline()
    server.recvline()

    for n_blocks in reversed(range(3)):
        prefix = b"0" * n_blocks * block_size
        for i in range(block_size):
            guess = b"0" * (block_size - (i+1))
            for c in string.printable:
                server.sendafter(b"> ", b"enc\n")
                tampered = bytes(prefix + guess + secret + c.encode() + guess)
                print("(" + str(n_blocks) + ", " + str(i) + ", " + c + "): " + str(tampered))
                server.sendafter(b"> ", tampered.hex().encode() + b"\n")
                output = server.recvline().decode()
                tamp = output[4*block_size:6*block_size]
                real = output[(3+2-n_blocks)*2*block_size:(4+2-n_blocks)*2*block_size]

                if real == tamp:
                    secret += c.encode()
                    break

    print("\n\nflag: " + secret.decode())
    server.close()
