
import pandas as pd
from datetime import datetime
import os

class CryptoLogger:
    def __init__(self):
        self.logs = []

    def log_encryption(self, operation, plaintext, ciphertext, private_key_curve, public_key_curve, hash_alg_name, salt, encrypt_time, decrypt_time, signature_time, verify_time, signature_valid, signature_size):
        record = {
            "Timestamp": datetime.now(),
            "Operation": operation,
            "Plaintext": plaintext if plaintext is not None else '',
            "Ciphertext": ciphertext if ciphertext is not None else '',
            "Plaintext Size": len(plaintext) if plaintext is not None else 0,
            "Ciphertext Size": len(ciphertext) if ciphertext is not None else 0,
            "Private Key Curve": private_key_curve,
            "Public Key Curve": public_key_curve,
            "Hash Algorithm": hash_alg_name,
            "Salt Size": len(salt) if salt is not None else 0,
            "Encryption Time": encrypt_time,
            "Decryption Time": decrypt_time,
            "Signature Time": signature_time,
            "Verification Time": verify_time,
            "Signature Valid": signature_valid,
            "Signature Size": signature_size
        }
        self.logs.append(record)

    def export_to_excel(self, filename):
        base_path = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(base_path, filename)
        df = pd.DataFrame(self.logs)
        if os.path.exists(file_path):
            existing_df = pd.read_excel(file_path)
            combined_df = pd.concat([existing_df, df], ignore_index=True)
        else:
            combined_df = df
        combined_df.to_excel(file_path, index=False)

crypto_logger = CryptoLogger()
