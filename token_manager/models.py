from django.db import models
from django.contrib.auth import get_user_model
from rest_framework.exceptions import AuthenticationFailed

from .consts import *

User = get_user_model()


class TokenLookUpIDManager(models.Manager):

    def create_token(self, user, **kwargs):
        """
        Manager method to create a token based on provided info and requested user.

        :param user: user that we wants the token be generated for.
        :param kwargs: including args like: ip, os, browser, device, device_type
        :return:
        """
        qs = self.filter(user=user)

        # First check if this user has exceeded maximum allowed tokens or not!
        if qs.count() >= NUM_ALLOWED_TOKENS_FOR_USER:
            # If this happened. remove latest token and create a new one

            if not user.is_staff:
                # Only keep allowed_tokens and remove the rest.
                last_tokens = qs.order_by('-created_at').values_list('id', flat=True)[:NUM_ALLOWED_TOKENS_FOR_USER - 1]
                remove_qs = qs.exclude(id__in=last_tokens)
                remove_qs.delete()

        # Now create a new user and assign an ID to it.
        return self.create(
            user=user,
            ip=kwargs.get('ip', ''),
            os=kwargs.get('os', ''),
            device=kwargs.get('device', ''),
            browser=kwargs.get('browser', ''),
            device_type=kwargs.get('device_type', '')
        )

    def check_token(self, user_id, lookup_id):
        """
        Manager method to check if token is valid or not.
        """
        if self.filter(user__id=user_id, id=lookup_id).exists():
            return True
        raise AuthenticationFailed('Token is not valid')


class TokenLookUpID(models.Model):
    """
    Main Model to control Tokens.
    The problem in JWT is that we can't control it,
    Once created Can't be deleted unless the expiration time arrives.
    """
    user = models.ForeignKey(
        to=User,
        db_index=True,
        on_delete=models.CASCADE,
    )

    ip = models.CharField(
        null=True,
        blank=True,
        max_length=15,
        verbose_name='IP Address'
    )
    os = models.CharField(
        null=True,
        blank=True,
        max_length=300,
        verbose_name='OS Name',
        help_text='ex: Android',
    )
    device_type = models.CharField(
        null=True,
        blank=True,
        max_length=6,
        help_text='ex: Mobile',
        verbose_name='Device Type',
        choices=DeviceTypeChoice.CHOICES,
    )
    device = models.CharField(
        null=True,
        blank=True,
        max_length=100,
        verbose_name='Device',
        help_text='ex: Samsung SM-A505F'
    )
    browser = models.CharField(
        null=True,
        blank=True,
        max_length=100,
        help_text='ex: Chrome Mobile WebView 103.0.50'
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = TokenLookUpIDManager()

    class Meta:
        db_table = 'token_manager_lookup_id'

    def __str__(self):
        return '{}, {}'.format(self.user.get_full_name(), self.id)
