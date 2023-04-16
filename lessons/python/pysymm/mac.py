import base64

from Crypto.Hash import HMAC, SHA3_256
from Crypto.Random import get_random_bytes
import json

if __name__ == '__main__':
    msg = b'This is the message used in input'

    secret = b'abcdefabcdefabcdefabcdef'

    hmac_generator = HMAC.new(secret, digestmod=SHA3_256)
    hmac_generator.update(msg[:5])
    hmac_generator.update(msg[5:])
    hmac_generator.digest()

    print("HMAC: "+hmac_generator.hexdigest())

    #creating json object
    obj = json.dumps({'message': msg.decode(), 'MAC': base64.b64encode(hmac_generator.digest()).decode() })
    print("JSON object: "+obj.__str__())

    #----------------------------------
    b64_obj = json.loads(obj)
    hmac_verifier = HMAC.new(secret, digestmod=SHA3_256)

    hmac_verifier.update(b64_obj['message'].encode())

    #injection for test
    mac = bytearray(base64.b64decode(b64_obj['MAC'].encode()))
    mac[0] = 0

    try:
        hmac_verifier.verify(mac)
        print("The message is authentic")
    except ValueError:
        print("Wrong message or secret!")
