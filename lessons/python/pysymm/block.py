from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

if __name__=='__main__':

    iv = get_random_bytes(AES.block_size)
    key = get_random_bytes(AES.key_size[2])

    plaintext = b'These are the data to encrypt !!'
    print(b"Plaintext: "+ plaintext)

    cipher_enc = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher_enc.encrypt(plaintext)
    print(b"Ciphertext: " + ciphertext)

    cipher_dec = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher_dec.decrypt(ciphertext)
    print(b"Decrypted: "+decrypted_data)

    print("\n")

    plaintext = b'Unaligned string...'
    cipher_enc = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext, AES.block_size)
    print(b"Padded plaintext: "+padded_data)
    ciphertext = cipher_enc.encrypt(padded_data)
    print(b"Ciphertext: " + ciphertext)

    cipher_dec = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher_dec.decrypt(ciphertext)
    print(b"Decrypted: " + decrypted_data)
    unpadded_data = unpad(decrypted_data, AES.block_size)
    print(b"Unpadded data: "+unpadded_data)