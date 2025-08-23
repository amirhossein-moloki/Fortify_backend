from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
from .models import SharedKey
from django.contrib.auth import get_user_model
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

User = get_user_model()

def get_or_create_shared_key(user1, user2):
    if user1.id > user2.id:
        user1, user2 = user2, user1

    try:
        shared_key = SharedKey.objects.get(user1=user1, user2=user2)
        return shared_key.key
    except SharedKey.DoesNotExist:
        # This is where the Diffie-Hellman key exchange would happen.
        # For now, we'll just generate a random key.
        key = os.urandom(32)
        encoded_key = base64.b64encode(key).decode()
        SharedKey.objects.create(user1=user1, user2=user2, key=encoded_key)
        return encoded_key

def derive_key_from_shared_secret(shared_secret, salt=b'salt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(shared_secret)

class Encryptor:
    def __init__(self, key):
        self.backend = default_backend()
        self.key = key

    def encrypt(self, plaintext):
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext

    def decrypt(self, ciphertext):
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode()

    def encrypt_file(self, input_file, output_file):
        iv = os.urandom(16)
        output_file.write(iv)

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()

        for chunk in iter(lambda: input_file.read(4096), b''):
            padded_chunk = padder.update(chunk)
            output_file.write(encryptor.update(padded_chunk))

        padded_chunk = padder.finalize()
        output_file.write(encryptor.update(padded_chunk))
        output_file.write(encryptor.finalize())

    def decrypt_file(self, input_file, output_file):
        iv = input_file.read(16)

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()

        unpadder = padding.PKCS7(128).unpadder()

        for chunk in iter(lambda: input_file.read(4096), b''):
            decrypted_chunk = decryptor.update(chunk)
            output_file.write(unpadder.update(decrypted_chunk))

        decrypted_chunk = decryptor.finalize()
        output_file.write(unpadder.update(decrypted_chunk))
        output_file.write(unpadder.finalize())
