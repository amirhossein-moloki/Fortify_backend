from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from .models import User

class UserRegistrationTest(APITestCase):
    def test_registration(self):
        """
        Ensure we can create a new user object.
        """
        url = reverse('register')
        data = {'username': 'testuser', 'password': 'testpassword123', 'password_confirm': 'testpassword123', 'email': 'test@example.com'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(User.objects.get().username, 'testuser')

class UserLoginTest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpassword123', email='test@example.com', is_active=True)

    def test_login(self):
        """
        Ensure user can login and get an OTP.
        """
        url = reverse('login')
        data = {'username': 'testuser', 'password': 'testpassword123'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertEqual(response.data['message'], 'Login successful! Please check your email for the OTP link.')

class UserProfileTest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpassword123', email='test@example.com', is_active=True)
        self.client.force_authenticate(user=self.user)

    def test_get_user_profile(self):
        """
        Ensure authenticated user can access their profile.
        """
        url = reverse('user_profile', kwargs={'username': self.user.username})
        response = self.client.get(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['is_owner'])
