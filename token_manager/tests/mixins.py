from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

User = get_user_model()


class TokenManagerTestMixin(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.admin_user = User.objects.create_superuser(
            username='admin',
            password='admin',
        )
        self.normal_user = User.objects.create_user(
            first_name='user',
            last_name='01',
            username='user',
            password='user',
        )
