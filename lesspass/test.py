import os
import unittest

from ed25519 import create_keypair

from lesspass.certificates import create_csr, create_certificate
from lesspass.certificates import verify_certificate, verify_certificate_chain


def create_certificate_(issuer_privkey=None):
    privkey, pubkey = create_keypair(os.urandom)
    cert = create_certificate(create_csr(pubkey, privkey),
                              issuer_privkey or privkey)

    return cert, privkey, pubkey


class Certificates(unittest.TestCase):
    def test_verify_self_signed_certificate(self):
        cert, _, _ = create_certificate_()
        self.assertTrue(verify_certificate(cert, cert))

    def test_verify_ca_signed_certificate(self):
        ca_cert, ca_privkey, _ = create_certificate_()
        cert, _, _ = create_certificate_(ca_privkey)
        self.assertTrue(verify_certificate(cert, ca_cert))
        self.assertFalse(verify_certificate(cert, cert))

        fake_ca, _, _ = create_certificate_()
        self.assertFalse(verify_certificate(cert, fake_ca))

    def test_verify_certificate_chain(self):
        ca_cert, ca_privkey, _ = create_certificate_()
        intermediate, intermediate_privkey, _ = create_certificate_(ca_privkey)
        end, _, _ = create_certificate_(intermediate_privkey)

        ca2_cert, ca2_privkey, _ = create_certificate_()
        intermediate2, _, _ = create_certificate_(ca2_privkey)

        certificate_chain = [end, intermediate, ca_cert]
        self.assertTrue(verify_certificate_chain(certificate_chain))

        broken_certificate_chain = [end, intermediate2, ca2_cert]
        self.assertFalse(verify_certificate_chain(broken_certificate_chain))
