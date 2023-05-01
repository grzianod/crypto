import os

from Crypto.Util.Padding import unpad

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run in an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from math import ceil
from pwn import *
from config import HOST, PORT
from data import cbc_oracle_ciphertext
from data import cbc_oracle_iv
from Crypto.Cipher import AES

def oracle_correct_padding_response():
    server = remote(HOST, PORT)
    server.send(cbc_oracle_iv)
    server.send(cbc_oracle_ciphertext)
    return server.recv(1024)


def oracle_wrong_padding_response():
    server = remote(HOST, PORT)
    server.send(cbc_oracle_iv)
    tampered = bytearray(cbc_oracle_ciphertext)
    tampered[len(cbc_oracle_ciphertext) - 1] = 0
    server.send(tampered)
    return server.recv(1024)


def query(iv, encrypted):
    server = remote(HOST, PORT)
    server.send(iv)
    server.send(encrypted)
    response = server.recv(1024)
    server.close()
    return response


def guess(c, p, ciphertext, block_size):
    current_index = len(ciphertext) - 1 - block_size - len(p)
    padding_value = len(p) + 1
    plain = bytearray()

    for c_ in range(0, 256):

        # tampered ciphertext construction
        tampered = bytearray(ciphertext[:current_index])
        tampered += c_.to_bytes(1, byteorder="big")
        for p_ in p:
            tampered += (p_ ^ padding_value).to_bytes(1, byteorder="big")
        tampered += ciphertext[len(ciphertext) - block_size: len(ciphertext)]

        # padding oracle query
        if query(cbc_oracle_iv, tampered) == correct_pad:
            print("c = "f'{c_:03d}', end=": ")
            p_ = padding_value ^ c_
            plain = bytes((p_ ^ ciphertext[current_index]).to_bytes(1, byteorder="big"))
            if plain == b"\x01":
                continue
            c.insert(0, c_)
            p.insert(0, p_)

    return plain


def guess_iv(c, p, iv, ciphertext, block_size):
    current_index = block_size - 1 - len(p)
    padding_value = len(p) + 1

    for c_ in range(0,256):

        # tampered iv construction
        tampered_iv = bytearray(iv[:current_index])
        tampered_iv += c_.to_bytes(1, byteorder="big")
        for p_ in p:
            tampered_iv += (p_ ^ padding_value).to_bytes(1, byteorder="big")

        if query(tampered_iv, ciphertext) == correct_pad:
            print("c = "f'{c_:03d}', end=": ")
            p_ = padding_value ^ c_
            c.insert(0, c_)
            p.insert(0, p_)
            return (p_ ^ iv[current_index]).to_bytes(1, byteorder="big")

    raise ValueError("No value from 0 to 255 founded!")



if __name__ == '__main__':

    correct_pad = oracle_correct_padding_response()
    wrong_pad = oracle_wrong_padding_response()

    n_blocks = ceil(len(cbc_oracle_ciphertext) / AES.block_size)
    plaintext = bytearray()

    for _ in range(n_blocks, 1, -1):
        c = []
        p = []

        for j in range(0, AES.block_size):
            plaintext[0:0] = guess(p, c, cbc_oracle_ciphertext, AES.block_size)
            print(plaintext)
        cbc_oracle_ciphertext = cbc_oracle_ciphertext[:-AES.block_size]

    c = []
    p = []
    for _ in range(0, AES.block_size):
        plaintext[0:0] = guess_iv(p, c, cbc_oracle_iv, cbc_oracle_ciphertext, AES.block_size)
        print(plaintext)

    print("\nMessage: " + str(plaintext))
    print("Unpadded message: " + str(unpad(plaintext, AES.block_size).decode()))
