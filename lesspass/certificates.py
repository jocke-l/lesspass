from operator import itemgetter
from typing import NewType, Tuple, List, Callable

from ed25519 import VerifyingKey, SigningKey, BadSignatureError

Signature = NewType('Signature', bytes)
SignedPublicKey = Tuple[VerifyingKey, Signature]

CSR = NewType('CSR', SignedPublicKey)
Certificate = NewType('Certificate', SignedPublicKey)
CertificateChain = NewType('CertificateChain', List[Certificate])

CA = Certificate
TrustedCAs = NewType('TrustedCAs', List[CA])

get_public_key: Callable[[Certificate], VerifyingKey] = itemgetter(0)
get_signature: Callable[[Certificate], Signature] = itemgetter(1)


def create_csr(public_key: VerifyingKey, private_key: SigningKey) -> CSR:
    return public_key, private_key.sign(public_key.to_bytes())


def create_certificate(csr: CSR, private_key: SigningKey) -> Certificate:
    get_public_key(csr).verify(get_signature(csr),
                               get_public_key(csr).to_bytes())

    return get_public_key(csr), private_key.sign(get_public_key(csr).to_bytes())


def verify_certificate(cert: Certificate, ca: CA) -> bool:
    try:
        get_public_key(ca).verify(get_signature(cert),
                                  get_public_key(cert).to_bytes())
    except (AssertionError, BadSignatureError):
        return False
    else:
        return True


def verify_certificate_chain(chain: CertificateChain):
    links = (
        (chain[i], chain[i + 1])
        for i in range(len(chain) - 1)
    )

    return all(verify_certificate(cert, issuer) for cert, issuer in links)


def is_self_signed_cert(cert: Certificate):
    return verify_certificate(cert, cert)
