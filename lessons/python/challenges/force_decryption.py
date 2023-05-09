import os

from Crypto.Random import get_random_bytes

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'  # Configuration patch to tell pwntools to not send terminal strings to be printed

from pwn import *
from math import ceil
from Crypto.Cipher import AES

HOST = "130.192.5.212"
PORT = 6523

if __name__ == '__main__':
    leak = b"mynamesuperadmin"
    iv = b"9dd3953de5da6d84ab06b7b4359cf317"
    tampered = bytes([d ^ o for d, o in zip(iv, leak)]).hex().encode()
    print(tampered)