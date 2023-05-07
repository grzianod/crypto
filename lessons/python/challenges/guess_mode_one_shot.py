import os

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'  # Configuration patch to tell pwntools to not send terminal strings to be printed

from pwn import *
from math import ceil
from Crypto.Cipher import AES

HOST = "130.192.5.212"
PORT = 6531

if __name__ == '__main__':
    server = remote(HOST, PORT)
    for i in range(128):
        challenge = server.recv(1024)
        if(i<10):
            print(str(challenge[:12]) + " OTP: ", end="")
            otp = challenge[32:96]
        if(i>=10 and i<100):
            print(str(challenge[:13]) + " OTP: ", end="")
            otp = challenge[33:97]
        if(i>=100):
            print(str(challenge[:14]) + " OTP: ", end="")
            otp = challenge[34:98]

        server.sendline(otp)
        sleep(0.5)
        ciphertext = server.recv(1024)[8:72]
        print(ciphertext)
        if(ciphertext[0:31] == ciphertext[32:63]):
            server.sendline(b"ECB")
        else:
            server.sendline(b"CBC")
        server.recvline()
        sleep(0.5)

    sleep(0.5)
    flag = server.recv(1024)
    print(flag)
    server.close()
