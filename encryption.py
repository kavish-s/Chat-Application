import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


# AES encryption class to handle encryption and decryption
class AES:
    def __init__(self, key):
        # Store the AES key and set up the cryptographic backend
        self.key = key
        self.backend = default_backend()

    def encrypt(self, plaintext):
        # Generate a random 16-byte IV (Initialization Vector)
        iv = os.urandom(16)

        # Set up the AES cipher with the key and CBC mode using the IV
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        # Pad the plaintext to ensure it fits the AES block size (128 bits)
        padder = PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Encrypt the padded data and prepend the IV to the ciphertext
        return iv + encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, ciphertext):
        # Extract the first 16 bytes as the IV for decryption
        iv = ciphertext[:16]

        # Set up the cipher for decryption using the same key and the extracted IV
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext (ignoring the IV)
        padded_plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()

        # Remove the padding from the plaintext and return the original message
        unpadder = PKCS7(128).unpadder()
        return unpadder.update(padded_plaintext) + unpadder.finalize()
