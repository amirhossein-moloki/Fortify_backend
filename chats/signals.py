from django.db.models.signals import post_save
from django.dispatch import receiver
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import Message, MutedChat
from notifications.models import Notification
from encryption.utils import Encryptor, get_or_create_shared_key
import base64

@receiver(post_save, sender=Message)
def create_message_notification(sender, instance, created, **kwargs):
    if created:
        message = instance
        chat = message.chat
        sender = message.sender

        # Get all participants except the sender
        participants = chat.participants.exclude(id=sender.id)

        for recipient in participants:
            # Check if the recipient has muted the chat
            is_muted = MutedChat.objects.filter(user=recipient, chat=chat).exists()
            if is_muted:
                continue  # Skip sending notification if chat is muted

            # Check notification settings of the user
            if not recipient.notification_settings.receive_messages:
                continue

            # Create notification content
            content = f'New message from {sender.username} in {chat.group_name or "a direct chat"}'

            # Encrypt the notification content for the recipient
            # Note: This uses a simplified key derivation for notifications.
            # A more robust system might use a different key management strategy for notifications.
            shared_key_str = get_or_create_shared_key(sender, recipient)
            shared_key = base64.b64decode(shared_key_str)
            encryptor = Encryptor(shared_key)

            encrypted_data = encryptor.encrypt(content)
            iv = encrypted_data[:16]
            encrypted_content = encrypted_data[16:]

            # Create the notification object
            notification = Notification.objects.create(
                recipient=recipient,
                sender=sender,
                notification_type='message',
                content=encrypted_content,
                iv=iv,
                related_object_id=chat.id,
                related_object_type='chat'
            )

            # Send real-time notification via WebSocket
            channel_layer = get_channel_layer()
            if channel_layer:
                async_to_sync(channel_layer.group_send)(
                    f'notifications_{recipient.id}',
                    {
                        'type': 'send_notification',
                        'message': {
                            'id': notification.id,
                            'content': base64.b64encode(notification.content).decode(),
                            'iv': base64.b64encode(notification.iv).decode(),
                            'type': notification.notification_type,
                            'sender': sender.username,
                            'is_read': notification.is_read,
                            'created_at': notification.created_at.isoformat()
                        }
                    }
                )
