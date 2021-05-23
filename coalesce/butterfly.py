import typing
import secrets
from dataclasses import dataclass
from Cryptodome.PublicKey import ECC
from . import ECIES
from . import sec_utils as su
from .caterpillar import Caterpillar
from .cocoon import CocoonKey


@dataclass
class ButterflyKey:
    """Class for Butterfly keys"""
    key_id: bytes  # XM: Name Component is bytes; a full name will involve application-layer semantics
    a_key: ECC.EccKey
    p_key: ECC.EccKey
    ck: bytes
    c: typing.Optional[ECC.EccKey] = None

    @staticmethod
    def generate(key_id):
        # DEVICE side
        # Algorithm 1: Generate Caterpillar Key
        return ButterflyKey(key_id=key_id,
                            a_key=ECC.generate(curve=su.ECC_CURVE),
                            p_key=ECC.generate(curve=su.ECC_CURVE),
                            ck=secrets.token_bytes(su.AES_KEY_BYTES))

    def to_public(self):
        # The public butterfly is sent to the CA
        return ButterflyKey(key_id=self.key_id,
                            a_key=self.a_key.public_key(),
                            p_key=self.p_key.public_key(),
                            ck=self.ck)

    def lay_egg(self, i: int) -> Caterpillar:
        # CA side
        # Algorithm 2 part 1: Generate Eggs from public ButterflyKeys
        if i < 0 or i >= (1 << 64):
            raise ValueError(f'Input {i=} should be a 64-bit integer')
        # Bi = self.a_key.pointQ + su.GEN_P256 * su.f_1(self.ck, i)
        bi_point = self.a_key.pointQ + ECC.EccKey(d=su.f_1(self.ck, i), curve=su.ECC_CURVE).pointQ

        # Algorithm 3: Generate final public keys (Caterpillar)
        final_pub_key = ECC.EccKey(point=bi_point + self.c.pointQ, curve=su.ECC_CURVE)
        return Caterpillar(key_id=su.f_name(self.key_id, i), pub_key=final_pub_key)

    def encrypt_kaleidoscope(self) -> bytes:
        # CA side
        # Algorithm 2 part 2: Encrypt kaleidoscope identity with P
        # Since c is shared by all i, we don't need to encrypt it multiple times
        kaleidoscope_bytes = bytes(self.c.export_key(format='DER', use_pkcs8=False))
        return ECIES.encrypt(self.p_key, kaleidoscope_bytes)

    def decrypt_kaleidoscope(self, kaleidoscope_encrypted: bytes):
        kaleidoscope_bytes = ECIES.decrypt(self.p_key, kaleidoscope_encrypted)
        self.c = ECC.import_key(kaleidoscope_bytes)

    def pupate_cocoon_key(self, i: int) -> CocoonKey:
        # DEVICE side
        # Algorithm 4: Derive Cocoon Private Keys from encrypted C
        if i < 0 or i >= (1 << 64):
            raise ValueError(f'Input {i=} should be a 64-bit integer')
        if self.c is None:
            raise ValueError(f'Cannot pupate cocoon without kaleidoscope gene')
        c = int(self.c.d)
        bi = int(self.a_key.d) + su.f_1(self.ck, i)
        final_prv_key = (bi + c) % su.SECP256R1_N
        return CocoonKey(key_id=su.f_name(self.key_id, i),
                         prv_key=ECC.EccKey(d=final_prv_key, curve=su.ECC_CURVE))

    def gen_kaleidoscope(self):
        self.c = ECC.generate(curve=su.ECC_CURVE)
