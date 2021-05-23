import typing
import secrets
from dataclasses import dataclass
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import ECC
import ndn.encoding as enc
#from . import ECIES


# Recommended Elliptic Curve Domain Parameters
# (from reference: https://stash.campllc.org/projects/SCMS/repos/crypto-test-vectors/browse)
ECC_CURVE = 'secp256r1'
SECP256R1_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
SECP256R1_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
SECP256R1_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
GEN_P256 = ECC.EccPoint(x=SECP256R1_GX, y=SECP256R1_GY, curve=ECC_CURVE)

AES_KEY_BYTES = 16
AES_KEY_BITS = 1 << AES_KEY_BYTES


def randint(inclusive_lower_bound: int, exclusive_upper_bound: int) -> int:
    return (inclusive_lower_bound +
            secrets.randbelow(exclusive_upper_bound - inclusive_lower_bound))


def f_k_int_x(k: bytes, x: int) -> int:
    r"""
    f_k^{int}(x) = (AES(k, x+1) XOR (x+1)) || (AES(k, x+2) XOR (x+2)) || (AES(k, x+3) XOR (x+3))

    :param k: the AES key (128-bit).
    :param x: the input block (128-bit).
    :return: the integer of f_k^{int}(x) % SECP256R1_N
    """
    assert len(k) == AES_KEY_BYTES
    aes_obj = AES.new(k, AES.MODE_ECB)
    ret = [0, 0, 0]
    for i in range(1, 4):
        xpi = (x + i).to_bytes(AES_KEY_BYTES, 'big')
        aes_xpi = aes_obj.encrypt(xpi)
        ret[i-1] = int.from_bytes(xpi, 'big') ^ int.from_bytes(aes_xpi, 'big')

    return ((ret[0] << AES_KEY_BITS << AES_KEY_BITS) | (ret[1] << AES_KEY_BITS) | ret[2]) % SECP256R1_N


# def expand_key(i: int,
#                exp: bytes,
#                seed: typing.Union[int, ECC.EccPoint],
#                exp_type: str = 'cert') -> typing.Tuple[int, ECC.EccPoint]:
#     r"""
#     Butterfly expansion for 'cert' and 'enc' keys

#     :param i: the ``i`` value for the corresponding certificate
#     :param exp: expansion value. An AES key (128-bit).
#     :param seed: the seed key, can be either private (1~SECP256R1_N-1) or public (EccPoint).
#     :param exp_type: the type of key expansion. "cert" (default) or "enc"
#     :return: a pair ``(pri, pub)`` of the private (if possible) and public key,
#         If ``seed`` is a private key, ``GEN_P256 * pri == pub``.
#         If ``seed`` is a public key, ``pri == 0``.
#     """

#     # x is the input to the expansion function
#     # 0^{32} || i || j || 0^{32}  for certificate
#     # 1^{32} || i || j || 0^{32}  for encryption key

#     if isinstance(seed, int):
#         prv = (seed + f_k_x) % SECP256R1_N
#         seed_pub = GEN_P256 * seed
#         pub = seed_pub + GEN_P256 * f_k_x
#     elif isinstance(seed, ECC.EccPoint):
#         prv = 0
#         pub = seed + GEN_P256 * f_k_x
#     else:
#         raise ValueError(f'Unsupported seed type: {seed}')

#     return prv, pub

def f_x(p0: int, exp: bytes, i: int):
    # Limit i to 64 bits
    j = i & ((1 << 64) - 1)
    x = (p0 << 96) | (j << 32) | 0
    return f_k_int_x(exp, x)


def f_1(exp: bytes, i: int):
    # x is the input to the expansion function
    # 0^{32} || i || j || 0^{32}  for certificate
    # 1^{32} || i || j || 0^{32}  for encryption key
    return f_x(0, exp, i)


def f_2(exp: bytes, i: int):
    # x is the input to the expansion function
    # 0^{32} || i || j || 0^{32}  for certificate
    # 1^{32} || i || j || 0^{32}  for encryption key
    return f_x((1 << 32) - 1, exp, i)


def f_name(key_id: bytes, i: int) -> bytes:
    # need to figure out NDN name derivation function
    pass


@dataclass
class ButterflyKey:
    """Class for Butterfly keys"""
    key_id: bytes  # XM: Name Component is bytes; a full name will involve application-layer semantics
    a: int
    A: ECC.EccPoint
    p: int
    P: ECC.EccPoint
    ck: bytes


    @staticmethod
    def generate():
        # Algorithm 1: Generate Caterpillar Key
        key_id = None  # generate keyId name
        a = randint(1, SECP256R1_N - 1)
        A = GEN_P256 * a
        p = randint(1, SECP256R1_N - 1)
        P = GEN_P256 * p
        ck = secrets.token_bytes(AES_KEY_BYTES)
        #ek = secrets.token_bytes(AES_KEY_BYTES)

        return ButterflyKey(key_id=key_id, a=a, A=A, p=p, P=P, ck=ck)


    def to_public(self):
        # TODO deal with keyId
        return ButterflyKey(key_id=self.key_id, a=0, A=self.A, p=0, P=self.P, ck=self.ck)
