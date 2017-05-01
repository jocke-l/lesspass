import ctypes
import struct
from base64 import urlsafe_b64encode, urlsafe_b64decode
from operator import itemgetter
from typing import NewType, Tuple, List, Callable, Union, Any

from ed25519 import VerifyingKey, SigningKey, BadSignatureError

PublicKey = NewType('PublicKey', Union[VerifyingKey, bytes, str])
Signature = NewType('Signature', Union[bytes, str])
SignedPublicKey = NewType('SignedPublicKey', Tuple[PublicKey, Signature])
Certificate = NewType('Certificate', Tuple[str, PublicKey, Signature])
EncodedCertificate = NewType('EncodedCertificate', Tuple[str, str, str])
CertificateChain = NewType('CertificateChain', List[Certificate])
CA = Certificate


def _null_terminated(getter) -> Callable[[Any], Union[str, bytes]]:
    def value(obj):
        got = getter(obj)
        if isinstance(got, bytes):
            return ctypes.create_string_buffer(got).value
        else:
            return got

    return value


def decode_certificate(name: str, public_key: str,
                       signature: str) -> Certificate:
    return (name, VerifyingKey(urlsafe_b64decode(public_key)),
            urlsafe_b64decode(signature.encode()))


def encode_certificate(name: str, pubkey: VerifyingKey,
                       signature: bytes) -> EncodedCertificate:
    return (name, urlsafe_b64encode(pubkey.to_bytes()).decode(),
            urlsafe_b64encode(signature).decode())


def create_certificate(name: str, pubkey: VerifyingKey,
                       privkey: SigningKey) -> Certificate:
    signature = privkey.sign(
        struct.pack(
            '255s32s',
            name.encode(),
            pubkey.to_bytes()
        )
    )

    return name, pubkey, signature


def verify_challenge(challenge: bytes, signature: bytes, cert: Certificate):
    try:
        get_public_key(cert).verify(signature, challenge)
    except (AssertionError, BadSignatureError):
        return False
    else:
        return True


def verify_certificate(cert: Certificate, ca: CA) -> bool:
    try:
        get_public_key(ca).verify(
            get_signature(cert),
            struct.pack('255s32s',
                        get_name(cert).encode(),
                        get_public_key(cert).to_bytes())
        )
    except (AssertionError, BadSignatureError):
        return False
    else:
        return True


def verify_certificate_chain(chain: CertificateChain,
                             trusted: List[Certificate]) -> bool:
    if len(chain) > 1:
        links = (
            (chain[i], chain[i + 1])
            for i in range(len(chain) - 1)
        )
    else:
        links = [(chain[0], chain[0])]

    return (all(verify_certificate(cert, issuer) for cert, issuer in links) and
            any(verify_certificate(chain[-1], ca) for ca in trusted))


def serialize_certificate(cert: Certificate) -> bytes:
    return urlsafe_b64encode(
        struct.pack(
            '255s32s64s',
            get_name(cert).encode(),
            get_public_key(cert).to_bytes(),
            get_signature(cert)
        )
    )


def deserialize_certificate(serialized_cert: bytes) -> Certificate:
    cert = struct.unpack('255s32s64s', urlsafe_b64decode(serialized_cert))

    return (get_name(cert).decode(), VerifyingKey(get_public_key(cert)),
            get_signature(cert))


def serialize_certificate_chain(certificate_chain: CertificateChain) -> bytes:
    return b'\n'.join(serialize_certificate(cert)
                      for cert in certificate_chain)


def deserialize_certificate_chain(serialized_certificate_chain: bytes) \
        -> CertificateChain:
    return [deserialize_certificate(cert)
            for cert in serialized_certificate_chain.split(b'\n')]


get_name: Callable[[Certificate], Union[str, bytes]] = \
    _null_terminated(itemgetter(0))
get_public_key: Callable[[Certificate], PublicKey] = itemgetter(1)
get_signature: Callable[[Certificate], Signature] = itemgetter(2)
