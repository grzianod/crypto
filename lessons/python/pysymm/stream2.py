import base64
import json
import sys

from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes

if __name__ == '__main__':

    key = get_random_bytes(Salsa20.key_size[1])
    nonce = get_random_bytes(8)

    cipher = Salsa20.new(key = key, nonce = nonce)

    fp_out = open(sys.argv[2], "wb")
    ciphertext = b''

    with open(sys.argv[1],"rb") as fp_in:
        plaintext = fp_in.read(1024)
        while plaintext:
            ciphertext += cipher.encrypt(plaintext)
            fp_out.write(ciphertext)
            plaintext = fp_in.read(1024)

    print("Nonce: "+base64.b64encode(cipher.nonce).decode())

    #informal way to put together crypto info -> JSON
    result = json.dumps({'ciphertext':base64.b64encode(ciphertext).decode(), 'nonce': base64.b64encode(nonce).decode()})
    print(result)