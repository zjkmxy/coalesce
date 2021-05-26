# This file defines the key derivation algorithm, independent with NDN
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
    # The base ECC key (a)
    base_key: ECC.EccKey
    # The generator seed AES key (ck+c) from CA
    seed: typing.Optional[bytes] = None

    @staticmethod
    def generate():
        # DEVICE side
        # Algorithm 1: Generate Master Key
        return MasterKey(base_key=ECC.generate(curve=ECC_CURVE))

    def to_public(self):
        # The public butterfly is sent to the CA
        return MasterKey(base_key=self.base_key.public_key(),
                         seed=self.seed)

    def pick_seed(self):
        self.seed = secrets.token_bytes(AES_KEY_BYTES)

    def encrypt_seed(self) -> bytes:
        # CA side
        # Algorithm 2 part 2: Encrypt kaleidoscope identity with P
        # Since c is shared by all i, we don't need to encrypt it multiple times
        return ECIES.encrypt(self.base_key, self.seed)

    def decrypt_seed(self, seed_encrypted: bytes):
        self.seed = ECIES.decrypt(self.base_key, seed_encrypted)

    @staticmethod
    def expand_key(seed: bytes, context: bytes, i: int) -> int:
        # Simplified version of f1, since we don't need to hide
        tmp = SHA256.new(context).digest()
        salt = bytearray(SHA256.digest_size)
        for j in range(SHA256.digest_size):
            salt[j] = tmp[j] ^ (i & 0xff)
            i = i >> 8
        key_bits = HKDF(seed, SHA256.digest_size, salt, SHA256)
        return int.from_bytes(key_bits, 'big') % SECP256R1_N

    def derive_public_key(self, context: bytes, i: int) -> ECC.EccKey:
        # CA side
        # Algorithm 2 part 1: Generate Eggs from public ButterflyKeys
        if i < 0:
            raise ValueError(f'Input {i=} should be a positive integer')
        if self.seed is None:
            raise ValueError(f'Cannot derive keys without seed')
        # Bi = self.a_key.pointQ + su.GEN_P256 * su.f_1(self.ck, i)
        bi_point = self.base_key.pointQ + ECC.EccKey(d=self.expand_key(self.seed, context, i), curve=ECC_CURVE).pointQ
        # Algorithm 3: Generate final public keys (Caterpillar)
        return ECC.EccKey(point=bi_point, curve=ECC_CURVE)

    def derive_private_key(self, context: bytes, i: int) -> ECC.EccKey:
        # DEVICE side
        # Algorithm 4: Derive Cocoon Private Keys from encrypted C
        if i < 0:
            raise ValueError(f'Input {i=} should be a positive integer')
        if self.seed is None:
            raise ValueError(f'Cannot derive keys without seed')
        bi = (int(self.base_key.d) + self.expand_key(self.seed, context, i)) % SECP256R1_N
        return ECC.EccKey(d=bi, curve=ECC_CURVE)
