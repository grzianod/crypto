from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from secrets import cbc_oracle_key as key
from data import cbc_oracle_iv as iv

cipher = AES.new(key,AES.MODE_CBC,iv)

msg = b'How many information could you extract using just one byte at a time?'

ctxt = cipher.encrypt(pad(msg,AES.block_size))

