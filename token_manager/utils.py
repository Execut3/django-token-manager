import jwt
import uuid
import warnings

from django.contrib.auth import get_user_model

from calendar import timegm
from datetime import datetime

from rest_framework_jwt.compat import get_username
from rest_framework_jwt.compat import get_username_field
from rest_framework_jwt.settings import api_settings

from .models import TokenLookUpID

User = get_user_model()


def jwt_get_secret_key(payload=None):
    """
    For enhanced security you may want to use a secret key based on user.

    This way you have an option to logout only this user if:
        - token is compromised
        - password is changed
        - etc.
    """
    if api_settings.JWT_GET_USER_SECRET_KEY:
        User = get_user_model()  # noqa: N806
        user = User.objects.get(pk=payload.get('user_id'))
        key = str(api_settings.JWT_GET_USER_SECRET_KEY(user))
        return key
    return api_settings.JWT_SECRET_KEY


def jwt_payload_handler(user, ip, r_type, browser, os, device):
    username_field = get_username_field()
    username = get_username(user)

    warnings.warn(
        'The following fields will be removed in the future: '
        '`email` and `user_id`. ',
        DeprecationWarning
    )

    # Create a lookupID for this user, also check if it exceeded max allowed or other situations...
    lookup_id = TokenLookUpID.objects.create_token(user, ip, r_type, browser, os, device)

    try:
        user.last_login = datetime.now()
        user.save()
    except Exception as e:
        print(e)

    # Update payload with new lookup_id, it is needed for verifications of token. Because when we revoke a token,
    # this lookup_id will not be available for this user anymore.
    payload = {
        'lookup_id': lookup_id.id,
        'user_id': user.pk,
        'username': username,
        'exp': datetime.utcnow() + api_settings.JWT_EXPIRATION_DELTA
    }
    if hasattr(user, 'email'):
        payload['email'] = user.email
    if isinstance(user.pk, uuid.UUID):
        payload['user_id'] = str(user.pk)

    payload[username_field] = username

    # Include original issued at time for a brand new token,
    # to allow token refresh
    if api_settings.JWT_ALLOW_REFRESH:
        payload['orig_iat'] = timegm(
            datetime.utcnow().utctimetuple()
        )

    if api_settings.JWT_AUDIENCE is not None:
        payload['aud'] = api_settings.JWT_AUDIENCE

    if api_settings.JWT_ISSUER is not None:
        payload['iss'] = api_settings.JWT_ISSUER

    return payload, lookup_id


def jwt_get_user_id_from_payload_handler(payload):
    """
    Override this function if user_id is formatted differently in payload
    """
    warnings.warn(
        'The following will be removed in the future. '
        'Use `JWT_PAYLOAD_GET_USERNAME_HANDLER` instead.',
        DeprecationWarning
    )

    return payload.get('user_id')


def jwt_get_username_from_payload_handler(payload):
    """
    Override this function if username is formatted differently in payload
    """
    return payload.get('username')


def jwt_encode_handler(payload):
    key = api_settings.JWT_PRIVATE_KEY or jwt_get_secret_key(payload)
    return jwt.encode(
        payload,
        key,
        api_settings.JWT_ALGORITHM
    ).decode('utf-8')


def jwt_decode_handler(token):
    options = {
        'verify_exp': api_settings.JWT_VERIFY_EXPIRATION,
    }
    # get user from token, BEFORE verification, to get user secret key
    unverified_payload = jwt.decode(token, None, False)
    secret_key = jwt_get_secret_key(unverified_payload)
    return jwt.decode(
        token,
        api_settings.JWT_PUBLIC_KEY or secret_key,
        api_settings.JWT_VERIFY,
        options=options,
        leeway=api_settings.JWT_LEEWAY,
        audience=api_settings.JWT_AUDIENCE,
        issuer=api_settings.JWT_ISSUER,
        algorithms=[api_settings.JWT_ALGORITHM]
    )


def jwt_response_payload_handler(token, user=None, request=None):
    """
    Returns the response data for both the login and refresh views.
    Override to return a custom response such as including the
    serialized representation of the User.

    Example:

    def jwt_response_payload_handler(token, user=None, request=None):
        return {
            'token': token,
            'user': UserSerializer(user, context={'request': request}).data
        }

    """
    # from permission.utils import get_user_permissions
    # from user_management.serializers import UserSerializer
    # user_data = UserSerializer().to_representation(user)
    # user_data['balance'] = user.wallet.balance
    return {
        'token': token,
        # 'user': user_data,
        # 'permissions': get_user_permissions(user)
    }


def get_lookup_id_from_request(request):
    auth_token = getattr(request, 'auth', None)
    lookup_id = None
    if auth_token:
        decoded_jwt = jwt_decode_handler(auth_token)
        lookup_id = decoded_jwt.get('lookup_id', None)
    return lookup_id


def delete_all_user_tokens(user_id):
    TokenLookUpID.objects.filter(user__id=user_id).delete()


def fetch_user_from_token(token):
    """
    This method simply, just retreive token as an argument, then tries to validate token and if the token is available,
    Then will return the corresponded user of it.
    :param token:
    :return:
    """
    try:
        decoded_jwt = jwt_decode_handler(token)
        user_id = decoded_jwt['user_id']
        lookup_id = decoded_jwt['lookup_id']
        token_obj = TokenLookUpID.objects.filter(user__id=user_id, id=lookup_id).first()
        if token_obj:
            return User.objects.get(id=user_id)
    except Exception as e:
        print(e)
        return None
    finally:
        return None


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def fetch_user_agent_info(user_agent):
    if type(user_agent) == str:
        r_type = user_agent
        browser = 'Other'
        os = user_agent
        device = user_agent
        return r_type, browser, os, device

    try:
        if user_agent.is_mobile:
            r_type = 'mobile'
        elif user_agent.is_tablet:
            r_type = 'tablet'
        elif user_agent.is_touch_capable:
            r_type = 'touch_capable'
        elif user_agent.is_pc:
            r_type = 'pc'
        elif user_agent.is_bot:
            r_type = 'bot'
        else:
            r_type = 'other'
    except:
        r_type = 'other'

    # Accessing user agent's browser attributes
    try:
        browser = '{} {}'.format(user_agent.browser.family, user_agent.browser.version_string)
    except:
        browser = 'Other'

    # Operating System properties
    try:
        os = '{} {}'.format(user_agent.os.family, user_agent.os.version_string)
    except:
        os = 'Other'

    # Device properties
    try:
        device = user_agent.device.family
    except:
        device = 'Other'

    return r_type, browser, os, device


def fetch_request_extra_info(request):
    custom_useragent = request.META.get('HTTP_USERAGENT', '')
    custom_machinehost = request.META.get('HTTP_MACHINE_HOST_NAME', '')
    if custom_machinehost or custom_useragent:
        r_type, browser, os, device = custom_useragent, custom_useragent, custom_useragent, custom_machinehost
    else:
        user_agent = request.user_agent
        r_type, browser, os, device = fetch_user_agent_info(user_agent)
    ip = get_client_ip(request)
    return ip, r_type, browser, os, device


def get_token_from_request(request, user):
    ip, r_type, browser, os, device = fetch_request_extra_info(request)
    payload, _ = jwt_payload_handler(user, ip, r_type, browser, os, device)
    return jwt_encode_handler(payload)
