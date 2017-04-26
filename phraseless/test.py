import os
import unittest

from ed25519 import create_keypair

from phraseless.certificates import create_certificate as create_certificate_
from phraseless.certificates import encode_certificate, decode_certificate
from phraseless.certificates import serialize_certificate
from phraseless.certificates import deserialize_certificate
from phraseless.certificates import verify_certificate, verify_certificate_chain
from phraseless.certificates import verify_challenge


def create_certificate(issuer_privkey=None):
    privkey, pubkey = create_keypair(os.urandom)
    cert = create_certificate_(b'Test', pubkey, issuer_privkey or privkey)

    return cert, privkey, pubkey


class Certificates(unittest.TestCase):
    def test_verify_self_signed_certificate(self):
        cert, *_ = create_certificate()
        self.assertTrue(verify_certificate(cert, cert))

    def test_verify_ca_signed_certificate(self):
        ca_cert, ca_privkey, _ = create_certificate()
        cert, *_ = create_certificate(ca_privkey)
        self.assertTrue(verify_certificate(cert, ca_cert))
        self.assertFalse(verify_certificate(cert, cert))

        fake_ca, *_ = create_certificate()
        self.assertFalse(verify_certificate(cert, fake_ca))

    def test_verify_certificate_chain(self):
        ca_cert, ca_privkey, _ = create_certificate()
        intermediate, intermediate_privkey, _ = create_certificate(ca_privkey)
        end, *_ = create_certificate(intermediate_privkey)

        ca2_cert, ca2_privkey, _ = create_certificate()
        intermediate2, *_ = create_certificate(ca2_privkey)

        certificate_chain = [end, intermediate, ca_cert]
        self.assertTrue(verify_certificate_chain(certificate_chain))

        self.assertTrue(verify_certificate_chain([ca_cert]))

        broken_certificate_chain = [end, intermediate2, ca2_cert]
        self.assertFalse(verify_certificate_chain(broken_certificate_chain))

        broken_certificate_chain_ = [end, ca_cert]
        self.assertFalse(verify_certificate_chain(broken_certificate_chain_))

        self.assertFalse(verify_certificate_chain([end]))

    def test_serialization(self):
        cert, *_ = create_certificate()
        cert_ = deserialize_certificate(serialize_certificate(cert))

        self.assertTrue(verify_certificate(cert_, cert))

    def test_authentication(self):
        cert, privkey, _ = create_certificate()
        _, fake_privkey, _ = create_certificate()

        challenge = os.urandom(32)
        signature = privkey.sign(challenge)
        self.assertTrue(verify_challenge(challenge, signature, cert))

        fake_signature = fake_privkey.sign(challenge)
        self.assertFalse(verify_challenge(challenge, fake_signature, cert))

    def test_encode_decode(self):
        cert, *_ = create_certificate()

        self.assertEqual(cert, decode_certificate(*encode_certificate(*cert)))

