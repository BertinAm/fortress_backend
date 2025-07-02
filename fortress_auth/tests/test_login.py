from django.contrib.auth.models import User
from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse
from ..models import LoginAttempt


class LoginAPITestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='correctpassword')
        self.login_url = reverse('login')  # This matches the path name in urls.py

    def test_successful_login(self):
        data = {
            'username': 'testuser',
            'password': 'correctpassword'
        }
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['detail'], 'Login successful')

    def test_failed_login(self):
        data = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'], 'Invalid credentials')

    def test_brute_force_block(self):
        data = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }
        # Simulate 5 failed attempts
        for _ in range(5):
            self.client.post(self.login_url, data)

        # 6th attempt should be blocked
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertIn('Too many failed attempts', response.data['detail'])

    def tearDown(self):
        LoginAttempt.objects.all().delete()
