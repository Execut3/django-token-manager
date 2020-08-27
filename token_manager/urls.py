from django.conf.urls import url, include
from rest_framework import routers

from .views import *

router = routers.DefaultRouter()

router.register(r'manage', JSONWebTokenView, basename='manage_tokens')


urlpatterns = [
    url(r'^get/', obtain_jwt_token, name='obtain_jwt_token'),
    url(r'^verify/', verify_jwt_token, name='verify_jwt_token'),
    url(r'^logout/', logout_view, name='logout_view'),

    url(r'^', include(router.urls)),

]
