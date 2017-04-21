import os
import unittest

from ed25519 import create_keypair

from lesspass.certificates import CA, create_csr, create_certificate
from lesspass.certificates import verify_certificate,verify_certificate_chain


def create_self_signed_certificate() -> CA:
    private_key, public_key = create_keypair(os.urandom)
    csr = create_csr(public_key, private_key)

    return create_certificate(csr, private_key)


class Certificates(unittest.TestCase):
    def test_verify_self_signed_certificate(self):
        cert = create_self_signed_certificate()

        self.assertTrue(verify_certificate(cert, cert))

    def test_verify_ca_signed_certificate(self):
        ca_private_key, ca_public_key = create_keypair(os.urandom)
        ca = create_certificate(create_csr(ca_public_key, ca_private_key),
                                ca_private_key)

        private_key, public_key = create_keypair(os.urandom)
        cert = create_certificate(create_csr(public_key, private_key),
                                  ca_private_key)

        self.assertTrue(verify_certificate(cert, ca))
        self.assertFalse(verify_certificate(cert, cert))

        fake_ca = create_self_signed_certificate()
        self.assertFalse(verify_certificate(cert, fake_ca))

    def test_verify_certificate_chain(self):
        ca_private_key, ca_public_key = create_keypair(os.urandom)
        ca = create_certificate(create_csr(ca_public_key, ca_private_key),
                                ca_private_key)

        intermediate_priv, intermediate_pub = create_keypair(os.urandom)
        intermediate = create_certificate(
            create_csr(intermediate_pub,
                       intermediate_priv),
            ca_private_key
        )

        end_private_key, end_public_key = create_keypair(os.urandom)
        end = create_certificate(create_csr(end_public_key, end_private_key),
                                 intermediate_priv)

        ca2_private_key, ca2_public_key = create_keypair(os.urandom)
        ca2 = create_certificate(create_csr(ca2_public_key, ca2_private_key),
                                 ca2_private_key)

        intermediate2_priv, intermediate2_pub = create_keypair(os.urandom)
        intermediate2 = create_certificate(
            create_csr(intermediate2_pub,
                       intermediate2_priv),
            ca2_private_key
        )

        certificate_chain = [end, intermediate, ca]
        self.assertTrue(verify_certificate_chain(certificate_chain))

        broken_certificate_chain = [end, intermediate2, ca2]
        self.assertFalse(verify_certificate_chain(broken_certificate_chain))
