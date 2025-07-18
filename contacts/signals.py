from django.db.models.signals import post_save
from django.dispatch import receiver
from notifications.models import Notification
from .models import Contact
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

@receiver(post_save, sender=Contact)
def create_contact_notification(sender, instance, created, **kwargs):
    if created and instance.status == 'pending':
        notification = Notification.objects.create(
            recipient=instance.contact,
            sender=instance.user,
            notification_type='friend_request',
            content=f'{instance.user.username} has sent you a friend request.',
            related_object_id=instance.id,
            related_object_type='contact'
        )
        channel_layer = get_channel_layer()
        if channel_layer:
            async_to_sync(channel_layer.group_send)(
                f'notifications_{instance.contact.id}',
                {
                    'type': 'send_notification',
                    'message': {
                        'id': notification.id,
                        'content': notification.content,
                        'type': notification.notification_type,
                        'sender': notification.sender.username,
                        'is_read': notification.is_read,
                        'created_at': notification.created_at.isoformat()
                    }
                }
            )
