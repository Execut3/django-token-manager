import django_jalali.db.models as jmodels

from django.db import models
from rest_framework.exceptions import AuthenticationFailed

from django.contrib.auth import get_user_model


NUM_ALLOWED_TOKENS_FOR_USER = 3


User = get_user_model()


class TokenLookUpIDManager(models.Manager):

    def create_token(self, user, ip, r_type, browser, os, device):
        user_tokens_queryset = self.filter(user=user)

        # First check if this user has exceeded maximum allowed tokens or not!
        if user_tokens_queryset.count() >= NUM_ALLOWED_TOKENS_FOR_USER:
            # If this happened. remove latest token and create a new one

            if not user.is_staff:
                last_tokens = user_tokens_queryset.order_by('-created_at')[:NUM_ALLOWED_TOKENS_FOR_USER-1]

                for token in user_tokens_queryset.exclude(id__in=last_tokens):
                    token.delete()

        # Now create a new user and assign an ID to it.
        return self.create(user=user, ip=ip, os=os[:30], browser=browser[:30],
                           device=device[:30], r_type=r_type[:30])

    def check_token(self, user_id, lookup_id):
        if self.filter(user__id=user_id, id=lookup_id).exists():
            return True
        raise AuthenticationFailed('توکن معتبر نیست.')


class TokenLookUpID(models.Model):
    """
    This is the main model to control tokens generated with jwt.\
    because of jwt, we don't have control on tokens after expire or user revoke.\
    So we map each created jwt token to an instance of this model.\

    For example if we define that only 3 active tokens\
    should be created for each user. we do as follow:
        - First create a jwt token for user, but first create\
        a lookupID for it and store that id in payload of jwt.
        - Then each time a request came with jwt, check payload\
        and see the provided lookup_id is in list of\
        lookupIDs for that user (max 3 is defined for this case)
        - each time user revoked this token or has been expired,\
        then remove lookup_id or assign a new one on jwt refresh.
    """
    # user_id = models.IntegerField(db_index=True)
    user = models.ForeignKey(User, db_index=True, on_delete=models.CASCADE)

    ip = models.CharField(max_length=20, null=True, blank=True)
    os = models.CharField(max_length=300, null=True, blank=True)
    r_type = models.CharField(max_length=20, null=True, blank=True)
    device = models.CharField(max_length=20, null=True, blank=True)
    browser = models.CharField(max_length=30, null=True, blank=True)

    created_at = jmodels.jDateTimeField(auto_now_add=True)
    updated_at = jmodels.jDateTimeField(auto_now=True)

    objects = TokenLookUpIDManager()

    class Meta:
        db_table = 'token_manager_lookup_id'

    def __str__(self):
        return '{}, {}'.format(self.user.get_full_name(), self.id)
