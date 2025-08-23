from django.test import TestCase
from channels.testing import WebsocketCommunicator
from django.contrib.auth import get_user_model
from .models import Chat, Message, Reaction
from Fortify_back.asgi import application
from encryption.utils import get_or_create_shared_key, Encryptor
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.test import APIClient
import json
import base64
from django.core.files.base import ContentFile
from io import BytesIO

User = get_user_model()

class ReactionTestCase(TestCase):
    def setUp(self):
        self.user1 = User.objects.create_user(username='user1', password='password')
        self.user2 = User.objects.create_user(username='user2', password='password')
        self.user3 = User.objects.create_user(username='user3', password='password')
        self.chat = Chat.objects.create(chat_type='direct')
        self.chat.participants.add(self.user1, self.user2)
        self.message = Message.objects.create(chat=self.chat, sender=self.user1, content=b'Test Message')
        self.client = APIClient()

    def test_create_reaction(self):
        reaction = Reaction.objects.create(message=self.message, user=self.user1, emoji='👍')
        self.assertEqual(Reaction.objects.count(), 1)
        self.assertEqual(reaction.emoji, '👍')

    def test_add_reaction_api(self):
        self.client.force_authenticate(user=self.user1)
        response = self.client.post(f'/api/chats/messages/{self.message.id}/react/', {'emoji': '❤️'}, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertEqual(Reaction.objects.count(), 1)
        self.assertEqual(Reaction.objects.first().emoji, '❤️')

    def test_remove_reaction_api(self):
        # First, add a reaction
        Reaction.objects.create(message=self.message, user=self.user1, emoji='❤️')
        self.assertEqual(Reaction.objects.count(), 1)

        # Now, remove it
        self.client.force_authenticate(user=self.user1)
        response = self.client.delete(f'/api/chats/messages/{self.message.id}/react/', {'emoji': '❤️'}, format='json')
        self.assertEqual(response.status_code, 204)
        self.assertEqual(Reaction.objects.count(), 0)

    def test_add_reaction_permission_denied(self):
        # user3 is not in the chat
        self.client.force_authenticate(user=self.user3)
        response = self.client.post(f'/api/chats/messages/{self.message.id}/react/', {'emoji': '👍'}, format='json')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(Reaction.objects.count(), 0)


class ChatTestCase(TestCase):
    def setUp(self):
        self.user1 = User.objects.create_user(username='user1', password='password')
        self.user2 = User.objects.create_user(username='user2', password='password')
        self.chat = Chat.objects.create()
        self.chat.participants.add(self.user1, self.user2)

    async def test_encrypted_chat(self):
        from channels.db import database_sync_to_async

        refresh1 = RefreshToken.for_user(self.user1)
        token1 = str(refresh1.access_token)
        communicator1 = WebsocketCommunicator(application, f"/ws/chat/{self.chat.id}/?token={token1}")
        connected1, _ = await communicator1.connect()
        self.assertTrue(connected1)

        refresh2 = RefreshToken.for_user(self.user2)
        token2 = str(refresh2.access_token)
        communicator2 = WebsocketCommunicator(application, f"/ws/chat/{self.chat.id}/?token={token2}")
        connected2, _ = await communicator2.connect()
        self.assertTrue(connected2)

        # User 1 sends a message
        message_text = "Hello, user2!"
        await communicator1.send_to(text_data=json.dumps({
            'action': 'send',
            'message': message_text,
        }))

        # Check that user 2 receives the decrypted message
        response = await communicator2.receive_from()
        data = json.loads(response)
        self.assertEqual(data['message'], message_text)

        # Check that the message is encrypted in the database
        message = await Message.objects.aget(chat=self.chat)
        shared_key_str = await database_sync_to_async(get_or_create_shared_key)(self.user1, self.user2)
        encryptor = Encryptor(base64.b64decode(shared_key_str))
        decrypted_content = encryptor.decrypt(message.content)
        self.assertEqual(decrypted_content, message_text)

        await communicator1.disconnect()
        await communicator2.disconnect()

class ChatFeaturesTestCase(TestCase):
    def setUp(self):
        self.user1 = User.objects.create_user(username='user1', password='password')
        self.user2 = User.objects.create_user(username='user2', password='password')
        self.chat = Chat.objects.create()
        self.chat.participants.add(self.user1, self.user2)

    async def test_reply_to_message(self):
        from channels.db import database_sync_to_async

        refresh1 = RefreshToken.for_user(self.user1)
        token1 = str(refresh1.access_token)
        communicator1 = WebsocketCommunicator(application, f"/ws/chat/{self.chat.id}/?token={token1}")
        await communicator1.connect()

        # Send the first message
        first_message_text = "First message"
        await communicator1.send_to(text_data=json.dumps({
            'action': 'send',
            'message': first_message_text,
        }))
        response1 = await communicator1.receive_from()
        data1 = json.loads(response1)
        message1_id = data1['message_id']

        reply_text = "This is a reply"
        await communicator1.send_to(text_data=json.dumps({
            'action': 'send',
            'message': reply_text,
            'reply_to': message1_id,
        }))

        # Wait for the message to be broadcasted back
        response2 = await communicator1.receive_from()
        data2 = json.loads(response2)
        self.assertEqual(data2['reply_to'], message1_id)

        await communicator1.disconnect()

    async def test_typing_indicator(self):
        refresh1 = RefreshToken.for_user(self.user1)
        token1 = str(refresh1.access_token)
        communicator1 = WebsocketCommunicator(application, f"/ws/chat/{self.chat.id}/?token={token1}")
        await communicator1.connect()

        refresh2 = RefreshToken.for_user(self.user2)
        token2 = str(refresh2.access_token)
        communicator2 = WebsocketCommunicator(application, f"/ws/chat/{self.chat.id}/?token={token2}")
        await communicator2.connect()

        await communicator1.send_to(text_data=json.dumps({'action': 'typing'}))

        response = await communicator2.receive_from()
        data = json.loads(response)
        self.assertEqual(data['type'], 'typing')
        self.assertEqual(data['user'], self.user1.username)

        await communicator1.disconnect()
        await communicator2.disconnect()

    async def test_attachment_encryption(self):
        from channels.db import database_sync_to_async
        refresh1 = RefreshToken.for_user(self.user1)
        token1 = str(refresh1.access_token)
        communicator1 = WebsocketCommunicator(application, f"/ws/chat/{self.chat.id}/?token={token1}")
        await communicator1.connect()

        file_content = b"This is a test file."
        file_data = {
            'content': base64.b64encode(file_content).decode(),
            'name': 'test.txt',
            'type': 'text/plain',
        }
        await communicator1.send_to(text_data=json.dumps({
            'action': 'send',
            'message': 'Here is a file.',
            'file': file_data,
        }))

        # Wait for the message to be broadcasted back
        response = await communicator1.receive_from()
        data = json.loads(response)
        message_id = data['message_id']

        message = await Message.objects.aget(id=message_id)
        attachment = await message.attachments.aget()

        shared_key_str = await database_sync_to_async(get_or_create_shared_key)(self.user1, self.user2)
        encryptor = Encryptor(base64.b64decode(shared_key_str))

        encrypted_file = attachment.file
        encrypted_file.open('rb')
        output_file = BytesIO()
        encryptor.decrypt_file(encrypted_file, output_file)
        output_file.seek(0)
        decrypted_content = output_file.read()

        self.assertEqual(decrypted_content, file_content)

        await communicator1.disconnect()

class PinMessageTestCase(TestCase):
    def setUp(self):
        self.user1 = User.objects.create_user(username='admin_user', password='password')
        self.user2 = User.objects.create_user(username='normal_user', password='password')
        self.chat = Chat.objects.create(chat_type='group', group_name='Test Group')
        self.chat.participants.add(self.user1, self.user2)
        self.chat.group_admin.add(self.user1)
        self.message = Message.objects.create(chat=self.chat, sender=self.user1, content=b'A message to pin')
        self.client = APIClient()

    def test_pin_message_api(self):
        self.client.force_authenticate(user=self.user1)
        response = self.client.post(f'/api/chats/chat/{self.chat.id}/pin/{self.message.id}/')
        self.assertEqual(response.status_code, 200)
        self.chat.refresh_from_db()
        self.assertEqual(self.chat.pinned_message.id, self.message.id)

    def test_unpin_message_api(self):
        # First, pin a message
        self.chat.pinned_message = self.message
        self.chat.save()

        self.client.force_authenticate(user=self.user1)
        response = self.client.delete(f'/api/chats/chat/{self.chat.id}/pin/{self.message.id}/')
        self.assertEqual(response.status_code, 204)
        self.chat.refresh_from_db()
        self.assertIsNone(self.chat.pinned_message)

    def test_pin_message_permission_denied(self):
        # user2 is not an admin
        self.client.force_authenticate(user=self.user2)
        response = self.client.post(f'/api/chats/chat/{self.chat.id}/pin/{self.message.id}/')
        self.assertEqual(response.status_code, 403)
