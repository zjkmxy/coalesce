import ECIES
from Cryptodome.PublicKey import ECC
from caterpillarCert import CaterpillarCert

@dataclass
class Caterpillar:
    """Class for public cocoon keys"""
    key_id: bytes  # Derived name f_name(key_id, i)
    Bi: ECC.EccPoint
    #Qi: ECC.EccPoint

    def hatch(self) -> typing.Tuple[bytes, CaterpillarCert]:
        # Algorithm 3: CertCoalesce generation
        # XM: Need to sign the certificate, but this involves the application layer semantics
        #     Specifically the application namespace
        c = ECC.generate(curve=ECC_CURVE)
        a_i_c = ECC.EccKey(point=self.Bi+c.public_key().pointQ, curve=ECC_CURVE)
        c_bytes = c.export_key(format='DER', use_pkcs8=False)
        C = ECIES.encrypt(ECC.EccKey(point=self.P, curve=ECC_CURVE), c_bytes)
        return C, CaterpillarCert(key_id=self.key_id, pub_key=a_i_c)
