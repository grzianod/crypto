from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from config import HOST, PORT
from pwn import *

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

if __name__ == '__main__':
    # server = remote(HOST, PORT)
    # username = b"Graziano"
    # server.send(username)
    # enc_cookie = server.recv(1024)
    #
    #
    # #after some time
    # server.send(enc_cookie)
    # ans = server.recv(1024)
    # print(ans)
    # server.close()
    #
    #
    # server = remote(HOST, PORT)
    # username = b"Graziano"
    # server.send(username)
    # enc_cookie = server.recv(1024)
    # edt = bytearray(enc_cookie)
    # edt[-1] = 0
    #
    #
    # server.send(edt)
    # ans = server.recv(1024)
    # print(ans)
    # server.close()

    username=b"Graziano"
    cookie = pad(b"username="+username+b",admin=0", AES.block_size) # sniffed from reverse engineering the server
    print(cookie)
    print(cookie[0:16], end=" || ")
    print(cookie[16:32])    #the second block should contain the string b'admin=0'

    # performing the changes
    index = cookie.index(b"0") % AES.block_size
    print(index)
    mask = ord(b"1") ^ ord(b"0")

    server = remote(HOST, PORT)
    server.send(username)
    enc_cookie = server.recv(1024)
    edt = bytearray(enc_cookie)
    edt[index] = enc_cookie[index] ^ mask

    server.send(edt)    # sacrifice the first block since the server uses CBC
    ans = server.recv(1024)
    print(ans)

