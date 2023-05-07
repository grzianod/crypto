import os

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'  # Configuration patch to tell pwntools to not send terminal strings to be printed

from pwn import *
from math import ceil
from Crypto.Cipher import AES

HOST = "130.192.5.212"
PORT = 6532

if __name__ == '__main__':
    server = remote(HOST, PORT)

    for i in range(128):
        challenge = server.recv(1024)
        if(i<10):
            print(challenge[:12].decode(), end=": ")
        if(i>=10 and i<100):
            print(challenge[:13].decode(), end=": ")
        if(i>=100):
            print(challenge[:14].decode(), end=": ")
        server.sendline(b'4d6e8776200910ac39ecf54673e8c04d5b157c40cd6f96874265b9b551c847d7')
        sleep(0.8)
        output1 = server.recv(1024)[8:71]
        server.sendline(b'4d6e8776200910ac39ecf54673e8c04d5b157c40cd6f96874265b9b551c847d7')
        sleep(0.8)
        output2 = server.recv(1024)[8:71]
        sleep(0.8)
        if(output1 == output2):
            print("ECB")
            server.sendline(b"ECB")
        else:
            print("CBC")
            server.sendline(b"CBC")
        sleep(0.8)
        print(server.recvline())

    print(server.recvline())
    server.close()
