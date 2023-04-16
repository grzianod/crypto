from Crypto.Hash import SHA256
from Crypto.Hash import SHA3_256

if __name__ == '__main__':

    hash_generator = SHA256.new()
    hash_generator.update(b'text to hash')
    hash_generator.update(b' even more text')
    print("Hash: "+hash_generator.hexdigest())
    print(b"Hash: " + hash_generator.digest())

    hash_generator = SHA3_256.new()
    with open(__file__, "rb") as fp_in:
        hash_generator.update(fp_in.read())
    print("Hash from file: "+ hash_generator.hexdigest())