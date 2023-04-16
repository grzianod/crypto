import hashlib
import hmac
from Crypto.Random import get_random_bytes

if __name__ == '__main__':

    dgst_generator = hashlib.sha256()
    dgst_generator.update(b'First chunck of data')
    dgst_generator.update(b'Second chucnk of data')

    print(dgst_generator.hexdigest())

    secret = get_random_bytes(32)
    mac_generator = hmac.new(secret, b'message to hash', hashlib.sha256)
    hmac_sender = mac_generator.hexdigest()

    #--------------------
    mac_gen_rec = hmac.new(secret, b'message to hash', hashlib.sha256())
    hmac_ver = mac_gen_rec.hexdigest()

    if hmac.compare_digest(hmac_sender, hmac_ver):
        print("HMACs are OK")
    else:
        print("HMACs are different")