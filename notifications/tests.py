from django.test import TestCase
from django.contrib.auth import get_user_model
from .models import Notification
from channels.testing import WebsocketCommunicator
from Fortify_back.asgi import application
from encryption.utils import Encryptor, derive_key_from_shared_secret
from channels.layers import get_channel_layer
import json
from rest_framework_simplejwt.tokens import RefreshToken
from channels.db import database_sync_to_async
import base64
import os

User = get_user_model()

class NotificationEncryptionTestCase(TestCase):
    def setUp(self):
        self.user1 = User.objects.create_user(username='user1', password='password')
        self.user2 = User.objects.create_user(username='user2', password='password')

    def test_notification_encryption(self):
        key = derive_key_from_shared_secret(self.user1.password.encode())
        encryptor = Encryptor(key)

        content = 'Test notification'
        encrypted_data = encryptor.encrypt(content)
        iv = encrypted_data[:16]
        encrypted_content = encrypted_data[16:]

        notification = Notification.objects.create(
            recipient=self.user1,
            sender=self.user2,
            notification_type='message',
            content=encrypted_content,
            iv=iv
        )

        decrypted_content = encryptor.decrypt(notification.iv + notification.content)
        self.assertEqual(decrypted_content, content)

    async def test_notification_consumer(self):
        key = derive_key_from_shared_secret(self.user1.password.encode())
        encryptor = Encryptor(key)

        content = 'Test notification'
        encrypted_data = encryptor.encrypt(content)
        iv = encrypted_data[:16]
        encrypted_content = encrypted_data[16:]

        notification = await self.create_notification(encrypted_content, iv)

        refresh = RefreshToken.for_user(self.user1)
        token = str(refresh.access_token)
        communicator = WebsocketCommunicator(application, f"/ws/notifications/?token={token}")
        connected, _ = await communicator.connect()
        self.assertTrue(connected)

        channel_layer = get_channel_layer()
        await channel_layer.group_send(
            f'notifications_{self.user1.id}',
            {
                'type': 'send_notification',
                'message': {
                    'id': notification.id,
                    'content': base64.b64encode(notification.content).decode(),
                    'iv': base64.b64encode(notification.iv).decode(),
                    'type': notification.notification_type,
                    'sender': self.user2.username,
                    'is_read': notification.is_read,
                    'created_at': notification.created_at.isoformat()
                }
            }
        )

        response = await communicator.receive_from()
        data = json.loads(response)
        self.assertEqual(data['message']['content'], content)

        await communicator.disconnect()

    @database_sync_to_async
    def create_notification(self, content, iv):
        return Notification.objects.create(
            recipient=self.user1,
            sender=self.user2,
            notification_type='message',
            content=content,
            iv=iv
        )
