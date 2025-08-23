from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from .models import User
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from unittest.mock import patch

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

    def test_registration_mismatched_passwords(self):
        """
        Ensure registration fails if passwords do not match.
        """
        url = reverse('register')
        data = {'username': 'testuser', 'password': 'testpassword123', 'password_confirm': 'testpassword456', 'email': 'test@example.com'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)

    def test_registration_existing_username(self):
        """
        Ensure registration fails if the username already exists.
        """
        User.objects.create_user(username='testuser', password='password', email='old@example.com')
        url = reverse('register')
        data = {'username': 'testuser', 'password': 'testpassword123', 'password_confirm': 'testpassword123', 'email': 'new@example.com'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('username', response.data)

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

    def test_login_invalid_password(self):
        """
        Ensure login fails with an invalid password.
        """
        url = reverse('login')
        data = {'username': 'testuser', 'password': 'wrongpassword'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['message'], 'Invalid credentials.')

    def test_login_nonexistent_user(self):
        """
        Ensure login fails for a user that does not exist.
        """
        url = reverse('login')
        data = {'username': 'nonexistentuser', 'password': 'password'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['message'], 'Invalid credentials.')

    def test_login_inactive_user(self):
        """
        Ensure login fails for an inactive user.
        """
        self.user.is_active = False
        self.user.save()
        url = reverse('login')
        data = {'username': 'testuser', 'password': 'testpassword123'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['message'], 'Account is not active. Please check your email for activation.')

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


class OTPVerificationTest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpassword123', email='test@example.com', is_active=True)
        self.url = reverse('otp_verify')

    def test_verify_otp_post_success(self):
        """
        Ensure OTP verification is successful with a valid OTP via POST.
        """
        self.user.otp = '123456'
        self.user.otp_expiration = timezone.now() + timedelta(minutes=5)
        self.user.save()

        data = {'otp': '123456'}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)

        # Check that OTP is cleared after use
        self.user.refresh_from_db()
        self.assertIsNone(self.user.otp)
        self.assertIsNone(self.user.otp_expiration)

    def test_verify_otp_post_invalid(self):
        """
        Ensure OTP verification fails with an invalid OTP.
        """
        self.user.otp = '123456'
        self.user.otp_expiration = timezone.now() + timedelta(minutes=5)
        self.user.save()

        data = {'otp': 'wrongotp'}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['message'], 'Invalid OTP.')

    def test_verify_otp_post_expired(self):
        """
        Ensure OTP verification fails with an expired OTP.
        """
        self.user.otp = '123456'
        self.user.otp_expiration = timezone.now() - timedelta(minutes=5)
        self.user.save()

        data = {'otp': '123456'}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['message'], 'OTP expired or invalid. Please request a new one.')

    def test_verify_otp_get_not_allowed(self):
        """
        Ensure GET requests to the OTP verify endpoint are not allowed.
        """
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


class PasswordResetTest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='oldpassword123', email='test@example.com', is_active=True)
        self.reset_url = reverse('password_reset')

    @patch('accounts.views.send_mail')
    def test_password_reset_request_success(self, mock_send_mail):
        """
        Ensure a user can request a password reset email.
        """
        response = self.client.post(self.reset_url, {'email': 'test@example.com'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Password reset email sent.')
        mock_send_mail.assert_called_once()

    @patch('accounts.views.send_mail')
    def test_password_reset_request_nonexistent_user(self, mock_send_mail):
        """
        Ensure the view doesn't reveal if a user email does not exist.
        """
        response = self.client.post(self.reset_url, {'email': 'nonexistent@example.com'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'If an account exists with this email, a password reset link has been sent.')
        mock_send_mail.assert_not_called()

    def test_password_reset_confirm_success(self):
        """
        Ensure a user can successfully reset their password with a valid token.
        """
        token = default_token_generator.make_token(self.user)
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        confirm_url = reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})

        data = {'password': 'newpassword123'}
        response = self.client.post(confirm_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Password has been reset successfully.')

        # Verify the password was actually changed
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpassword123'))
        self.assertFalse(self.user.check_password('oldpassword123'))

    def test_password_reset_confirm_invalid_token(self):
        """
        Ensure password reset fails with an invalid token.
        """
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        confirm_url = reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': 'invalid-token'})

        data = {'password': 'newpassword123'}
        response = self.client.post(confirm_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['message'], 'Token is invalid or expired.')

    def test_password_reset_confirm_no_password(self):
        """
        Ensure password reset fails if a new password is not provided.
        """
        token = default_token_generator.make_token(self.user)
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        confirm_url = reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})

        data = {} # No password
        response = self.client.post(confirm_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['message'], 'Password not provided.')


class SearchUserViewTest(APITestCase):
    def setUp(self):
        self.user1 = User.objects.create_user(username='user1', password='password123', email='user1@example.com')
        self.user2 = User.objects.create_user(username='user2', password='password123', email='user2@example.com')
        self.url = reverse('search_user')

    def test_search_user_unauthenticated(self):
        """
        Ensure unauthenticated users cannot access the search endpoint.
        """
        response = self.client.get(self.url, {'username': 'user2'})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_search_user_authenticated_success(self):
        """
        Ensure authenticated users can successfully search for other users.
        """
        self.client.force_authenticate(user=self.user1)
        response = self.client.get(self.url, {'username': 'user2'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'user2')

    def test_search_user_not_found(self):
        """
        Ensure the endpoint handles searches for non-existent users.
        """
        self.client.force_authenticate(user=self.user1)
        response = self.client.get(self.url, {'username': 'nonexistent'})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
