from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from .models import Contact, Block

User = get_user_model()

class ContactAPITestCase(TestCase):
    def setUp(self):
        self.user1 = User.objects.create_user(username='user1', password='password123')
        self.user2 = User.objects.create_user(username='user2', password='password123')
        self.client = APIClient()

    def test_create_contact(self):
        self.client.force_authenticate(user=self.user1)
        response = self.client.post('/api/contacts/add/', {'contact': self.user2.id})
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Contact.objects.count(), 1)
        contact = Contact.objects.first()
        self.assertEqual(contact.user, self.user1)
        self.assertEqual(contact.contact, self.user2)
        self.assertEqual(contact.status, 'pending')

    def test_friend_request_action(self):
        contact = Contact.objects.create(user=self.user1, contact=self.user2)
        self.client.force_authenticate(user=self.user2)
        response = self.client.put(f'/api/contacts/friend-request/{contact.id}/accept/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        contact.refresh_from_db()
        self.assertEqual(contact.status, 'accepted')
        self.assertTrue(Contact.objects.filter(user=self.user2, contact=self.user1, status='accepted').exists())

    def test_friend_request_action_reject(self):
        contact = Contact.objects.create(user=self.user1, contact=self.user2)
        self.client.force_authenticate(user=self.user2)
        response = self.client.put(f'/api/contacts/friend-request/{contact.id}/reject/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        contact.refresh_from_db()
        self.assertEqual(contact.status, 'rejected')
        self.assertFalse(Contact.objects.filter(user=self.user2, contact=self.user1, status='accepted').exists())


class BlockUserTestCase(TestCase):
    def setUp(self):
        self.user1 = User.objects.create_user(username='user1', password='password123')
        self.user2 = User.objects.create_user(username='user2', password='password123')
        self.client = APIClient()

    def test_block_user(self):
        self.client.force_authenticate(user=self.user1)
        response = self.client.post(f'/api/contacts/block/{self.user2.username}/')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(Block.objects.filter(blocker=self.user1, blocked=self.user2).exists())

    def test_unblock_user(self):
        Block.objects.create(blocker=self.user1, blocked=self.user2)
        self.client.force_authenticate(user=self.user1)
        response = self.client.delete(f'/api/contacts/block/{self.user2.username}/')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Block.objects.filter(blocker=self.user1, blocked=self.user2).exists())

    def test_block_self(self):
        self.client.force_authenticate(user=self.user1)
        response = self.client.post(f'/api/contacts/block/{self.user1.username}/')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
