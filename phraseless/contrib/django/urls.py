from django.conf.urls import url

from phraseless.contrib.django.views import authenticate

urlpatterns = [
    url(r'^auth/$', authenticate)
]
