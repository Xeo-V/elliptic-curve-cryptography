from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os, time

def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()

def derive_key(private_key, public_key, salt, hash_alg):
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(algorithm=hash_alg, length=32, salt=salt, info=b'handshake data', backend=default_backend()).derive(shared_key)
    return derived_key

def encrypt(receiver_public_key, sender_private_key, plaintext, hash_alg):
    start_time = time.time()
    salt = os.urandom(16)
    symmetric_key = derive_key(sender_private_key, receiver_public_key, salt, hash_alg)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    end_time = time.time()
    return iv + ciphertext, salt, end_time - start_time

def decrypt(receiver_private_key, sender_public_key, ciphertext, salt, hash_alg):
    start_time = time.time()
    symmetric_key = derive_key(receiver_private_key, sender_public_key, salt, hash_alg)
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    end_time = time.time()
    return plaintext, end_time - start_time

def sign(private_key, data, hash_alg):
    start_time = time.time()
    signature = private_key.sign(data, ec.ECDSA(hash_alg))
    end_time = time.time()
    return signature, end_time - start_time

def verify(public_key, signature, data, hash_alg):
    r = int.from_bytes(signature[:32], 'big')
    s = int.from_bytes(signature[32:], 'big')
    try:
        public_key.verify(encode_dss_signature(r, s), data, ec.ECDSA(hash_alg))
        return True
    except InvalidSignature:
        return False
