import ctypes
import struct
from base64 import b64encode, b64decode
from operator import itemgetter
from typing import NewType, Tuple, List, Callable, Union, Any

from ed25519 import VerifyingKey, SigningKey, BadSignatureError

PublicKey = NewType('PublicKey', Union[VerifyingKey, bytes])
Signature = NewType('Signature', bytes)
SignedPublicKey = NewType('SignedPublicKey', Tuple[PublicKey, Signature])
Certificate = NewType('Certificate', Tuple[bytes, PublicKey, Signature])
CertificateChain = NewType('CertificateChain', List[Certificate])
CA = Certificate


def _null_terminated(getter) -> Callable[[Any], bytes]:
    def value(obj) -> bytes:
        return ctypes.create_string_buffer(getter(obj))

    return value


def create_certificate(name: bytes, pubkey: VerifyingKey,
                       privkey: SigningKey) -> Certificate:
    signature = privkey.sign(struct.pack('255s32s', name, pubkey.to_bytes()))

    return name, pubkey, signature


def verify_certificate(cert: Certificate, ca: CA) -> bool:
    try:
        get_public_key(ca).verify(
            get_signature(cert),
            struct.pack('255s32s',
                        get_name(cert),
                        get_public_key(cert).to_bytes())
        )
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


def serialize_certificate(cert: Certificate) -> bytes:
    return b64encode(
        struct.pack(
            '255s32s64s',
            get_name(cert),
            get_public_key(cert).to_bytes(),
            get_signature(cert)
        )
    )


def deserialize_certificate(serialized_cert: bytes) -> Certificate:
    cert = struct.unpack('255s32s64s', b64decode(serialized_cert))

    return (get_name(cert), VerifyingKey(get_public_key(cert)),
            get_signature(cert))


get_name: Callable[[Certificate], bytes] = itemgetter(0)
get_public_key: Callable[[Certificate], PublicKey] = itemgetter(1)
get_signature: Callable[[Certificate], Signature] = itemgetter(2)
