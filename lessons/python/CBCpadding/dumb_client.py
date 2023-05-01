import string

from Crypto.Cipher import AES
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from data import cbc_oracle_iv as iv
from data import cbc_oracle_ciphertext as ciphertext
from pwn import *

from config import HOST, PORT

if __name__ == '__main__':
    # server = remote(HOST, PORT)
    # server.send(iv)
    # server.send(ciphertext)
    # response = server.recv(1024)
    # print(response)
    # server.close()

    # ----------------------------------------
    N = len(ciphertext)//AES.block_size
    initial_part = ciphertext[:(N-2)*AES.block_size]
    tomodify_block = bytearray(ciphertext[(N-2)*AES.block_size:(N-1)*AES.block_size])
    last_part = ciphertext[(N-1)*AES.block_size:]

    byte_index = AES.block_size-1   # last element index of the tomodify_block
    c15 = tomodify_block[byte_index]

    for c_prime_15 in range(256):
        tomodify_block[byte_index] = c_prime_15
        tosend = initial_part + tomodify_block + last_part
        server = remote(HOST, PORT)
        server.send(iv)
        server.send(tosend)
        response = server.recv(1024)
        server.close()

        if response == b"OK":   # there could be false positives!
            print("c_prime_15: "+str(c_prime_15))
            p_prime_15 = c_prime_15 ^ 1 # 1 is the padding value that the oracle is expecting to be there
            p15 = p_prime_15 ^ c15
            print("p_prime_15: " + str(p_prime_15))
            print("p15: " + str(p15))

    print("----------------------")
    p_prime_15 = 197
    c_second_15 = p_prime_15 ^ 2  # 2 is the padding value that the oracle is expecting to be there
    tomodify_block[byte_index] = c_second_15
    byte_index -= 1
    c14 = tomodify_block[byte_index]

    for c_prime_14 in range(256):
        tomodify_block[byte_index] = c_prime_14
        tosend = initial_part + tomodify_block + last_part

        server = remote(HOST, PORT)
        server.send(iv)
        server.send(tosend)
        response = server.recv(1024)
        server.close()

        if response == b"OK":
            print("c_prime_14: " + str(c_prime_14))
            p_prime_14 = c_prime_14 ^ 2  # 1 is the padding value that the oracle is expecting to be there
            p14 = p_prime_14 ^ c14
            print("p_prime_14: " + str(p_prime_14))
            print("p14: " + str(p14))

    print("----------------------")
    p_prime_14 = 89
    c_second_14 = p_prime_14 ^ 3  # 3 is the padding value that the oracle is expecting to be there
    tomodify_block[byte_index] = c_second_14
    byte_index -= 1
    c13 = tomodify_block[byte_index]

    for c_prime_13 in range(256):
        tomodify_block[byte_index] = c_prime_13
        tosend = initial_part + tomodify_block + last_part

        server = remote(HOST, PORT)
        server.send(iv)
        server.send(tosend)
        response = server.recv(1024)
        server.close()

        if response == b"OK":
            print("c_prime_13: " + str(c_prime_13))
            p_prime_13 = c_prime_13 ^ 3  # 1 is the padding value that the oracle is expecting to be there
            p13 = p_prime_13 ^ c13
            print("p_prime_13: " + str(p_prime_13))
            print("p13: " + str(p13))




