import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import UserAsymmetricKey
from django.contrib.auth import get_user_model

User = get_user_model()

class KeyExchangeConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope['user']
        if self.user.is_anonymous:
            await self.close()
            return

        await self.accept()

    async def receive(self, text_data):
        data = json.loads(text_data)
        action = data.get('action')

        if action == 'send_public_key':
            public_key = data.get('public_key')
            private_key = data.get('private_key') # This should be encrypted on the client
            await self.save_public_key(public_key, private_key)

        elif action == 'get_public_key':
            username = data.get('username')
            public_key = await self.get_public_key(username)
            await self.send(text_data=json.dumps({
                'action': 'public_key',
                'username': username,
                'public_key': public_key,
            }))

    @database_sync_to_async
    def save_public_key(self, public_key, private_key):
        UserAsymmetricKey.objects.update_or_create(
            user=self.user,
            defaults={'public_key': public_key, 'private_key': private_key}
        )

    @database_sync_to_async
    def get_public_key(self, username):
        try:
            user = User.objects.get(username=username)
            user_key = UserAsymmetricKey.objects.get(user=user)
            return user_key.public_key
        except (User.DoesNotExist, UserAsymmetricKey.DoesNotExist):
            return None
