import json
from channels.generic.websocket import AsyncWebsocketConsumer
from encryption.utils import Encryptor, derive_key_from_shared_secret
import base64

class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope['user']
        if self.user.is_anonymous:
            await self.close()
            return

        self.room_name = f'user_{self.user.id}_notifications'
        self.room_group_name = f'notifications_{self.user.id}'
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def send_notification(self, event):
        notification_data = event['message']

        key = derive_key_from_shared_secret(self.user.password.encode())
        encryptor = Encryptor(key)

        encrypted_content = base64.b64decode(notification_data['content'])
        iv = base64.b64decode(notification_data['iv'])

        decrypted_content = encryptor.decrypt(iv + encrypted_content)

        notification_data['content'] = decrypted_content

        await self.send(text_data=json.dumps({
            'message': notification_data
        }))
