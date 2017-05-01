from base64 import urlsafe_b64encode, urlsafe_b64decode

from django.contrib.auth import get_user_model
from django.test import TestCase, Client

from phraseless.certificates import encode_certificate
from phraseless.certificates import get_public_key, get_signature
from phraseless.certificates import serialize_certificate_chain
from phraseless.contrib.django.models import Certificate
from phraseless.test import create_certificate


class Authentication(TestCase):
    def setUp(self):
        self.client = Client()
        self.test_user = get_user_model().objects.create_user('test')

        self.ca_cert, ca_privkey, _ = create_certificate()
        self.cert, self.privkey, _ = create_certificate(ca_privkey)

        encoded_cert = encode_certificate(*self.ca_cert)

        Certificate.objects.create(
            user=self.test_user,
            public_key=get_public_key(encoded_cert),
            signature=get_signature(encoded_cert)
        )

    def test_challenge_middleware(self):
        response = self.client.get('/')
        response_ = self.client.get('/')

        self.assertIn('X-Challenge', response)
        self.assertIn('X-Challenge', response_)
        self.assertNotEqual(response['X-Challenge'], response_['X-Challenge'])

    def test_authentication(self):
        certificate_chain = serialize_certificate_chain(
            [self.cert, self.ca_cert]
        ).decode()

        challenge = self.client.get('/')['X-Challenge']
        challenge_signature = urlsafe_b64encode(
            self.privkey.sign(urlsafe_b64decode(challenge))
        ).decode()

        payload = {'certificate_chain': certificate_chain,
                   'challenge_signature': challenge_signature}
        response = self.client.post('/auth/', data=payload)

        self.assertIn('X-Authenticated', response)
        self.assertEqual(response['X-Authenticated'], 'yes')
