from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

#alice or bob
parameters = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend())  #long term parameters

#alice
private_key_alice = parameters.generate_private_key()

#bob
public_key_bob = parameters.generate_private_key().public_key()

#alice
shared_secret = private_key_alice.exchange(public_key_bob)

derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'just agreed data',
    backend=default_backend()
).derive(shared_secret)


#ephemeral
private_key_alice2 = parameters.generate_private_key()
public_key_bob2 = parameters.generate_private_key().public_key()
shared_secret2 = private_key_alice.exchange(public_key_bob2)
derived_key2 = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'just agreed data',
    backend=default_backend()
).derive(shared_secret2)