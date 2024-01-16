
import ecc_algorithms
import utilFn
from cryptography.hazmat.primitives import hashes

def main():
    crypto_logger = utilFn.crypto_logger

    private_key1, public_key1 = ecc_algorithms.generate_keys()
    private_key2, public_key2 = ecc_algorithms.generate_keys()

    plaintext = b"Hello23222oo, ECC!"
    hash_alg = hashes.SHA256()

    encrypted_message, salt, encrypt_time = ecc_algorithms.encrypt(public_key2, private_key1, plaintext, hash_alg)
    decrypted_message, decrypt_time = ecc_algorithms.decrypt(private_key2, public_key1, encrypted_message, salt, hash_alg)

    signature, signature_time = ecc_algorithms.sign(private_key1, plaintext, hash_alg)
    is_valid, _ = ecc_algorithms.verify(public_key1, signature, plaintext, hash_alg)
    crypto_logger.log_encryption(
        "Encryption", 
        plaintext, 
        encrypted_message, 
        "SECP256R1",  
        "SECP256R1",  
        hash_alg.name,
        salt,
        encrypt_time,
        decrypt_time,
        signature_time,
        verify_time,
        is_valid,
        len(signature)
    )

    crypto_logger.export_to_excel('encryption_logs.xlsx')

    print("Encrypted message:", encrypted_message)
    print("Decrypted message:", decrypted_message)
    print("Signature valid:", is_valid)

if __name__ == "__main__":
    main()
