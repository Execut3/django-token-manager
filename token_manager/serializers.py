import jwt
from django.contrib.auth import authenticate, get_user_model
from django.utils.translation import ugettext as _
from rest_captcha.serializers import RestCaptchaSerializer
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from token_manager.utils import get_client_ip, get_lookup_id_from_request, \
    fetch_request_extra_info
from .compat import Serializer, get_username_field, PasswordField
from .models import TokenLookUpID
from .settings import api_settings

User = get_user_model()
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER
jwt_get_username_from_payload = api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER


class JSONWebTokenSerializer(Serializer):
    """
    Serializer class used to validate a username and password.

    'username' is identified by the custom UserModel.USERNAME_FIELD.

    Returns a JSON Web Token that can be used to authenticate later calls.
    """

    def __init__(self, *args, **kwargs):
        """
        Dynamically add the USERNAME_FIELD to self.fields.
        """
        super(JSONWebTokenSerializer, self).__init__(*args, **kwargs)

        self.fields[self.username_field] = serializers.CharField()
        self.fields['password'] = PasswordField(write_only=True)

    @property
    def username_field(self):
        return get_username_field()

    def validate(self, attrs):
        credentials = {
            self.username_field: attrs.get(self.username_field),
            'password': attrs.get('password')
        }

        if all(credentials.values()):
            user = authenticate(**credentials)

            if user:
                if not user.is_active:
                    # msg = 'حساب کاربری فعال نیست.'
                    msg = 'Account is not active.'
                    raise serializers.ValidationError(msg)

                request = self.context.get('request', None)

                ip, r_type, browser, os, device = fetch_request_extra_info(request)

                payload, lookup_id = jwt_payload_handler(user, ip, r_type, browser, os, device)

                return {
                    'token': jwt_encode_handler(payload),
                    'user': user
                }
            else:
                # msg = 'امکان ورود با اطلاعات ارائه شده وجود ندارد.'
                msg = 'Unable to login with provided credentials.'
                raise serializers.ValidationError(msg)
        else:
            msg = _('Must include "{username_field}" and "password".')
            msg = msg.format(username_field=self.username_field)
            raise serializers.ValidationError(msg)


# class JSONWebTokenWithCaptchaSerializer(RestCaptchaSerializer, JSONWebTokenSerializer):
class JSONWebTokenWithCaptchaSerializer(JSONWebTokenSerializer):
    pass


class VerificationBaseSerializer(Serializer):
    """
    Abstract serializer used for verifying and refreshing JWTs.
    """
    token = serializers.CharField()

    def validate(self, attrs):
        msg = 'Please define a validate method.'
        raise NotImplementedError(msg)

    def _check_payload(self, token):
        # Check payload valid (based off of JSONWebTokenAuthentication,
        # may want to refactor)
        try:
            payload = jwt_decode_handler(token)
        except jwt.ExpiredSignature:
            msg = _('Signature has expired.')
            raise serializers.ValidationError(msg)
        except jwt.DecodeError:
            msg = _('Error decoding signature.')
            raise serializers.ValidationError(msg)

        return payload

    def _check_user(self, payload):
        username = jwt_get_username_from_payload(payload)

        if not username:
            msg = _('Invalid payload.')
            raise serializers.ValidationError(msg)

        # Make sure user exists
        try:
            user = User.objects.get_by_natural_key(username)
        except User.DoesNotExist:
            msg = _("User doesn't exist.")
            raise serializers.ValidationError(msg)

        if not user.is_active:
            msg = _('User account is disabled.')
            raise serializers.ValidationError(msg)

        return user


class VerifyJSONWebTokenSerializer(VerificationBaseSerializer):
    """
    Check the veracity of an access token.
    """

    # private = False

    def post_task_after_token_valid(self, token_obj):
        # set new ip address
        try:
            new_ip = get_client_ip(self.context.get('request'))
            token_obj.ip = new_ip
        except:
            pass

        token_obj.save()

    def validate(self, attrs):
        token = attrs['token']

        payload = self._check_payload(token=token)
        user = self._check_user(payload=payload)

        lookup_id = payload.get('lookup_id')
        user_id = user.id
        token_obj = TokenLookUpID.objects.filter(user__id=user_id, id=lookup_id).first()
        if token_obj:
            self.post_task_after_token_valid(token_obj)

            return {
                'token': token,
                'user': user
            }
        # raise ValidationError('توکن دیگر معتبر نیست.')
        raise ValidationError('Token is not valid anymore!')


class VerifyJSONWebTokenPrivateSerializer(VerifyJSONWebTokenSerializer):

    def post_task_after_token_valid(self, token_obj):
        pass

    # private = True


class LookUpIDSerializer(serializers.ModelSerializer):
    class Meta:
        model = TokenLookUpID
        fields = '__all__'

    def to_representation(self, instance):
        r = super(LookUpIDSerializer, self).to_representation(instance)
        current = False
        request = self.context.get('request')

        # Find out which token user is using.
        lookup_id = get_lookup_id_from_request(request)
        if lookup_id == instance.id:
            current = True

        r.update({
            'current': current
        })
        return r


class DeleteListOfTokenSerializer(serializers.Serializer):
    id_list = serializers.PrimaryKeyRelatedField(queryset=TokenLookUpID.objects.all(), many=True,
                                                 required=True, allow_empty=False)
