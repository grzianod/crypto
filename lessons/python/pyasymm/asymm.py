from Crypto.Util.number import getPrime

n_length = 1024
p1 = getPrime(n_length)
p2 = getPrime(n_length)
print("p1: "+str(p1))
print("p2: "+str(p2)) 

n=p1*p2
print("p1*p2: "+str(n)) 

phi = (p1-1)*(p2-1)

#define public exponent
e = 65537

from math import gcd
g = gcd(e,phi)
if g != 1:
    raise ValueError

d = pow(e, -1, phi) #providing a third parameter to pow() it calculate a^b mod c
print("d: "+str(d)) 

public_rsa_key = (e,n)
private_rsa_key = (d,n)

#encryption
msg = b'this is the message to encrypt'
msg_int = int.from_bytes(msg, byteorder='big')
print("msg: " + str(msg_int))

if msg_int > n-1:
    raise ValueError

enc = pow(msg_int, e, n)
print("cipher: " + str(enc))

#decryption
dec = pow(enc, d, n)
print("decipher: " + str(dec))
msg_dec = dec.to_bytes(n_length, byteorder='big')
print("msg: " + str(msg_dec))   #there could be padding!