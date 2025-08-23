from django.test import TestCase
from django.contrib.auth import get_user_model
from .utils import Encryptor, get_or_create_shared_key, derive_key_from_shared_secret
from .models import SharedKey
import os
import base64

User = get_user_model()

class EncryptionTestCase(TestCase):
    def setUp(self):
        self.user1 = User.objects.create_user(username='user1', password='password')
        self.user2 = User.objects.create_user(username='user2', password='password')

    def test_encryptor(self):
        key = os.urandom(32)
        encryptor = Encryptor(key)
        plaintext = "This is a secret message."
        ciphertext = encryptor.encrypt(plaintext)
        decrypted_plaintext = encryptor.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted_plaintext)

    def test_get_or_create_shared_key(self):
        key1_str = get_or_create_shared_key(self.user1, self.user2)
        key1 = base64.b64decode(key1_str)
        key2_str = get_or_create_shared_key(self.user2, self.user1)
        key2 = base64.b64decode(key2_str)
        self.assertEqual(key1, key2)

        # Check that the key is stored in the database
        shared_key = SharedKey.objects.get(user1=self.user1, user2=self.user2)
        self.assertEqual(key1_str, shared_key.key)

    def test_derive_key_from_shared_secret(self):
        shared_secret = b'shared_secret'
        key = derive_key_from_shared_secret(shared_secret)
        self.assertEqual(len(key), 32)
