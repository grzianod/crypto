import os

from Crypto.Random import get_random_bytes

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'  # Configuration patch to tell pwntools to not send terminal strings to be printed

from pwn import *
from math import ceil
from Crypto.Cipher import AES

HOST = "130.192.5.212"
PORT = 6543
block_size = 16

def print_format(output):
    for z in range(len(output)):
        if z % 32 == 0:
            print(" " + str(ceil(z / 32)), end=": ")
        print(output[z:z + 1], end="")

if __name__ == '__main__':

    secret = b""
    server = remote(HOST, PORT)

    last = b""
    padding = 0
    for i in range(block_size):
        server.recvline()
        server.recvline()
        server.recvline()
        server.recvline()
        guess = i * b"0" + block_size*6 * b"1"
        server.sendafter(b"> ", b"enc\n")
        server.sendafter(b"> ", guess.hex().encode() + b"\n")
        print(guess.hex().encode())
        output = server.recvline()[:32]
        if output == last:
            padding = i-1
            break
        last = output

    print("padding: " + str(padding))

    for n_blocks in reversed(range(3)):
        prefix = b"-" * n_blocks * block_size
        for i in range(block_size):
            guess = b"-" * (block_size - (i+1))
            for c in string.printable:
                server.sendafter(b"> ", b"enc\n")
                tampered = bytes(padding* b"-" + prefix + guess + secret + c.encode() + guess)
                print("(" + str(n_blocks) + ", " + str(i) + ", " + c + "): " + str(tampered[3:]))
                server.sendafter(b"> ", tampered.hex().encode() + b"\n")
                output = server.recvline().decode()[32:]
                tamp = output[2 * 2 * block_size:3 * 2 * block_size]
                real = output[(3 + 2 - n_blocks) * 2 * block_size:(4 + 2 - n_blocks) * 2 * block_size]

                if real == tamp:
                    secret += c.encode()
                    break

    print("\n\nflag: " + secret.decode())
    server.close()
