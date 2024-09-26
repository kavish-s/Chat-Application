import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AES:
    def __init__(self, key: bytes):
        self.key = key
        self.backend = default_backend()

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = os.urandom(16)  # Random IV for each encryption
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        # Padding plaintext to block size (16 bytes)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted  # Return IV + encrypted message

    def decrypt(self, ciphertext: bytes) -> bytes:
        iv = ciphertext[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()

        # Unpadding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext
