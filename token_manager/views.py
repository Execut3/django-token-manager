from datetime import datetime

from rest_framework import status, mixins
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet

from .models import TokenLookUpID
from .serializers import (
    JSONWebTokenSerializer, VerifyJSONWebTokenSerializer, LookUpIDSerializer,
    DeleteListOfTokenSerializer, JSONWebTokenWithCaptchaSerializer)
from .settings import api_settings
from .utils import jwt_decode_handler, get_lookup_id_from_request

jwt_response_payload_handler = api_settings.JWT_RESPONSE_PAYLOAD_HANDLER


class JSONWebTokenAPIView(APIView):
    """
    Base API View that various JWT interactions inherit from.
    """
    permission_classes = ()
    authentication_classes = ()

    def get_serializer_context(self):
        """
        Extra context provided to the serializer class.
        """
        return {
            'request': self.request,
            'view': self,
        }

    def get_serializer_class(self):
        """
        Return the class to use for the serializer.
        Defaults to using `self.serializer_class`.
        You may want to override this if you need to provide different
        serializations depending on the incoming request.
        (Eg. admins get full serialization, others get basic serialization)
        """
        assert self.serializer_class is not None, (
                "'%s' should either include a `serializer_class` attribute, "
                "or override the `get_serializer_class()` method."
                % self.__class__.__name__)
        return self.serializer_class

    def get_serializer(self, *args, **kwargs):
        """
        Return the serializer instance that should be used for validating and
        deserializing input, and for serializing output.
        """
        serializer_class = self.get_serializer_class()
        kwargs['context'] = self.get_serializer_context()
        return serializer_class(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            user = serializer.object.get('user') or request.user
            token = serializer.object.get('token')

            response_data = jwt_response_payload_handler(token, user, request)

            # get lookup_id from payload
            # payload = jwt_decode_handler(token)
            # lookup_id = payload.get('lookup_id')
            # token_lookup = TokenLookUpID.objects.filter(user__id=user.id, id=lookup_id).first()
            # if token_lookup:
            #     response_data.update({
            #         'extra': {
            #             'r_type': token_lookup.r_type, 'ip': token_lookup.ip,
            #             'device': token_lookup.device, 'os': token_lookup.os,
            #             'browser': token_lookup.browser, 'created_at': str(token_lookup.created_at),
            #         }
            #     })

            response = Response(response_data)
            if api_settings.JWT_AUTH_COOKIE:
                expiration = (datetime.utcnow() +
                              api_settings.JWT_EXPIRATION_DELTA)
                response.set_cookie(api_settings.JWT_AUTH_COOKIE,
                                    token,
                                    expires=expiration,
                                    httponly=True)
            return response

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ObtainJSONWebToken(JSONWebTokenAPIView):
    """
    API View that receives a POST with a user's username and password.

    Returns a JSON Web Token that can be used for authenticated requests.
    """
    serializer_class = JSONWebTokenSerializer


class ObtainJSONWebTokenAdmin(ObtainJSONWebToken):

    serializer_class = JSONWebTokenWithCaptchaSerializer


class VerifyJSONWebToken(JSONWebTokenAPIView):
    """
    API View that checks the veracity of a token, returning the token if it
    is valid.
    """
    serializer_class = VerifyJSONWebTokenSerializer


class JSONWebTokenView(mixins.RetrieveModelMixin,
                       mixins.DestroyModelMixin,
                       mixins.ListModelMixin,
                       GenericViewSet):
    serializer_class = LookUpIDSerializer
    pagination_class = None

    def get_queryset(self):
        request_user = self.request.user
        queryset = TokenLookUpID.objects.all()

        if not request_user.is_staff:
            queryset = TokenLookUpID.objects.filter(user__id=request_user.id)

        user_id = self.request.query_params.get('user_id', '')
        if user_id:
            queryset = queryset.filter(user__id=user_id)
        return queryset

    def get_object(self):
        obj = super(JSONWebTokenView, self).get_object()
        if self.request.user == obj.user or self.request.user.is_staff:
            return obj
        # raise ValidationError('دسترسی لازم به این توکن را ندارید.')
        raise ValidationError('You don\'t have access to this token!')

    @action(detail=False, methods=['post'], url_path='delete-list', serializer_class=DeleteListOfTokenSerializer)
    def delete_tokens_by_list(self, request, **kwargs):

        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():

            tokens = serializer.validated_data.get('id_list')

            # Remove current token from list if exist (Should not be able to remove token that is sending this request.)
            current_token_id = get_lookup_id_from_request(request)
            current_token = TokenLookUpID.objects.filter(id=current_token_id).first()
            if current_token in tokens:
                tokens.remove(current_token)

            token_users = []
            for t in tokens:
                if not t.user in token_users:
                    token_users.append(t.user)

            # If not is_staff, can only access tokens of his own.
            if not self.request.user.is_staff:
                for u in token_users:
                    if not self.request.user == u:
                        # raise ValidationError('شما دسترسی لازم برای حذف این توکن‌ها را ندارید.')
                        raise ValidationError('You don\'t have required permissions to do this operation!')

            count = len(tokens)
            for token in tokens:
                token.delete()

            # return Response('تعداد {} توکن با موفقیت حذف شدند.'.format(count), status=status.HTTP_204_NO_CONTENT)
            return Response('Total {} tokens removed successfully.'.format(count), status=status.HTTP_204_NO_CONTENT)

        return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)


class RemoveTokenView(APIView):
    """
    Api view to logout user and remove it's token
    """

    def get(self, request, *args, **kwargs):
        try:
            lookup_id = get_lookup_id_from_request(request)
            token = TokenLookUpID.objects.get(id=lookup_id)
            token.delete()
        except Exception as e:
            print(e)
            # raise ValidationError('کاربر وارد نشده است')
            raise ValidationError('User is not login!')
        # return Response({'status_code': 200, 'message': 'کاربر با موفقیت خارج شد.'})
        return Response({'status_code': 200, 'message': 'User successfully exited.'})

    def post(self, request, *args, **kwargs):
        try:
            lookup_id = get_lookup_id_from_request(request)
            token = TokenLookUpID.objects.get(id=lookup_id)
            token.delete()
        except Exception as e:
            print(e)
            # raise ValidationError('کاربر وارد نشده است')
            raise ValidationError('User is not login!')
        # return Response({'status_code': 200, 'message': 'کاربر با موفقیت خارج شد.'})
        return Response({'status_code': 200, 'message': 'User successfully exited.'})


logout_view = RemoveTokenView.as_view()


obtain_jwt_token = ObtainJSONWebToken.as_view()
obtain_jwt_token_admin = ObtainJSONWebTokenAdmin.as_view()
verify_jwt_token = VerifyJSONWebToken.as_view()
