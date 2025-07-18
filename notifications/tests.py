from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from .models import Notification, NotificationSettings

User = get_user_model()

class NotificationAPITestCase(TestCase):
    def setUp(self):
        self.user1 = User.objects.create_user(username='user1', password='password123')
        self.user2 = User.objects.create_user(username='user2', password='password123')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user1)

    def test_notification_list(self):
        Notification.objects.create(recipient=self.user1, sender=self.user2, notification_type='message', content='Test notification')
        response = self.client.get('/api/notifications/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_notification_mark_as_read(self):
        notification = Notification.objects.create(recipient=self.user1, sender=self.user2, notification_type='message', content='Test notification')
        response = self.client.put(f'/api/notifications/{notification.id}/mark-as-read/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        notification.refresh_from_db()
        self.assertTrue(notification.is_read)

    def test_notification_delete(self):
        notification = Notification.objects.create(recipient=self.user1, sender=self.user2, notification_type='message', content='Test notification')
        response = self.client.delete(f'/api/notifications/{notification.id}/delete/')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Notification.objects.count(), 0)

    def test_notification_settings_retreive(self):
        response = self.client.get('/api/notifications/settings/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_notification_settings_update(self):
        response = self.client.put('/api/notifications/settings/', {'receive_messages': False})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(NotificationSettings.objects.get(user=self.user1).receive_messages)
