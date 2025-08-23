from django.db import models
from django.conf import settings

class Notification(models.Model):
    NOTIFICATION_TYPES = (
        ('message', 'پیام جدید'),
        ('friend_request', 'درخواست دوستی'),
        ('group_invite', 'دعوت به گروه'),
        ('mention', 'منشن شدن'),
    )

    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='sent_notifications', null=True, blank=True)
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    content = models.BinaryField(null=True)
    iv = models.BinaryField(null=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    related_object_id = models.PositiveIntegerField(null=True, blank=True)
    related_object_type = models.CharField(max_length=50, null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

class NotificationSettings(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notification_settings')
    receive_messages = models.BooleanField(default=True)
    receive_friend_requests = models.BooleanField(default=True)
    receive_group_invites = models.BooleanField(default=True)
    receive_mentions = models.BooleanField(default=True)

    def __str__(self):
        return f"Notification Settings for {self.user.username}"