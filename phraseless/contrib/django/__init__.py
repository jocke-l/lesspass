import os
from base64 import urlsafe_b64encode, urlsafe_b64decode

from django.contrib.auth import get_user_model
from django.utils.deprecation import MiddlewareMixin
from urllib.parse import urlencode

from phraseless.certificates import get_name
from phraseless.certificates import verify_challenge, verify_certificate_chain


class PhraselessChallengeMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        if not request.user.is_authenticated:
            challenge = urlsafe_b64encode(os.urandom(32)).decode()
            request.session['auth_challenge'] = challenge
            response['X-Challenge'] = challenge

        return response


class PhraselessAuthBackend:
    def authenticate(self, request, certificate_chain=None, signature=None):
        user_model = get_user_model()

        try:
            user = user_model.objects.get(
                username=get_name(certificate_chain[0])
            )
        except user_model.DoesNotExist:
            return None

        valid_chain = verify_certificate_chain(
            certificate_chain,
            user.certificates.all().to_tuples()
        )
        valid_challenge_signature = verify_challenge(
            urlsafe_b64decode(request.session['auth_challenge']),
            signature,
            certificate_chain[0]
        )

        if valid_chain and valid_challenge_signature:
            return user

    def get_user(self, user_id):
        user_model = get_user_model()

        try:
            user_model.objects.get(pk=user_id)
        except user_model.DoesNotExist:
            return None


default_app_config = 'phraseless.contrib.django.apps.PhraselessConfig'
