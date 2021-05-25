import typing
import secrets
from dataclasses import dataclass
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Protocol.KDF import HKDF
from . import ECIES


ECC_CURVE = 'secp256r1'
SECP256R1_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
AES_KEY_BYTES = 16
AES_KEY_BITS = 1 << AES_KEY_BYTES


@dataclass
class MasterKey:
    """
    This is a class for pure security algorithms without application semantics
    """
    # The base ECC key
    base_key: ECC.EccKey
    # The generator AES key
    gen: bytes
    # The secret c from CA
    c: typing.Optional[ECC.EccKey] = None

    @staticmethod
    def generate():
        # DEVICE side
        # Algorithm 1: Generate Master Key
        return MasterKey(base_key=ECC.generate(curve=ECC_CURVE),
                         gen=secrets.token_bytes(AES_KEY_BYTES))

    def to_public(self):
        # The public butterfly is sent to the CA
        return MasterKey(base_key=self.base_key.public_key(),
                         gen=self.gen)

    def random_pick_c(self):
        self.c = ECC.generate(curve=ECC_CURVE)

    def encrypt_c(self) -> bytes:
        # CA side
        # Algorithm 2 part 2: Encrypt kaleidoscope identity with P
        # Since c is shared by all i, we don't need to encrypt it multiple times
        c_bytes = bytes(self.c.export_key(format='DER', use_pkcs8=False))
        return ECIES.encrypt(self.base_key, c_bytes)

    def decrypt_c(self, c_encrypted: bytes):
        c_bytes = ECIES.decrypt(self.base_key, c_encrypted)
        self.c = ECC.import_key(c_bytes)

    @staticmethod
    def expand_key(gen: bytes, context: bytes, i: int) -> int:
        # Simplified version of f1, since we don't need to hide
        seed = SHA256.new(context).digest()
        salt = bytearray(SHA256.digest_size)
        for j in range(SHA256.digest_size):
            salt[j] = seed[j] ^ (i & 0xff)
            i = i >> 16
        key_bits = HKDF(gen, SHA256.digest_size, salt, SHA256)
        return int.from_bytes(key_bits, 'big') % SECP256R1_N

    def derive_public_key(self, context: bytes, i: int) -> ECC.EccKey:
        # CA side
        # Algorithm 2 part 1: Generate Eggs from public ButterflyKeys
        if i < 0:
            raise ValueError(f'Input {i=} should be a positive integer')
        if self.c is None:
            raise ValueError(f'Cannot derive keys without c')
        # Bi = self.a_key.pointQ + su.GEN_P256 * su.f_1(self.ck, i)
        bi_point = self.base_key.pointQ + ECC.EccKey(d=self.expand_key(self.gen, context, i), curve=ECC_CURVE).pointQ
        # Algorithm 3: Generate final public keys (Caterpillar)
        return ECC.EccKey(point=bi_point + self.c.pointQ, curve=ECC_CURVE)

    def derive_private_key(self, context: bytes, i: int) -> ECC.EccKey:
        # DEVICE side
        # Algorithm 4: Derive Cocoon Private Keys from encrypted C
        if i < 0:
            raise ValueError(f'Input {i=} should be a positive integer')
        if self.c is None:
            raise ValueError(f'Cannot derive keys without c')
        c = int(self.c.d)
        bi = int(self.base_key.d) + self.expand_key(self.gen, context, i)
        return ECC.EccKey(d=(bi + c) % SECP256R1_N, curve=ECC_CURVE)
