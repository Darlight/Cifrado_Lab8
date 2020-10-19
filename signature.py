from Crypto.PublicKey import RSA
from hashlib import sha512

# Generates de public key and private key
keyPair = RSA.generate(bits=1024)

print("Value of n: ", keyPair.n)
print("Public key: ", keyPair.e)
print("Private key: ", keyPair.d)

msg = b'Josue Sagastume'
# Hash of the message
hash = int.from_bytes(sha512(msg).digest(), byteorder = 'big')
print("\nHash: ", hash)

# Calculate de digital signature using hash**privatekey mod n
signature = pow(hash,keyPair.d, keyPair.n)
print("\nSignature: ", signature)

# Verifying the signature by decrypting the signature using de public key
# (signature**publickey mod n) and comparing the obtained hash from the 
# signature to the hash of the original message

hash_from_signature = pow(signature, keyPair.e, keyPair.n)
print("\nHash obtained from de signature: ", hash_from_signature)

print("\nSignature valid: ", hash == hash_from_signature)

