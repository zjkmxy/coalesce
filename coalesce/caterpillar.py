import typing
from dataclasses import dataclass
from Cryptodome.PublicKey import ECC
from ndn.encoding import FormalName
from .utils import derive_cert


@dataclass
class Caterpillar:
    """Class for public caterpillar keys"""
    key_id: bytes
    pub_key: ECC.EccKey

    def derive_cert(self, name_prefix, signer, expire_sec) -> typing.Tuple[FormalName, bytes]:
        # Derive cocoon certificate
        public_key_der = bytes(self.pub_key.export_key(format='DER'))
        cert_name, cert = derive_cert(name_prefix + [self.key_id], b'coalesce', public_key_der, signer, expire_sec)
        return cert_name, cert
