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
class CocoonsKey:
    key_id: bytes
    prv_key: ECC.EccKey


# XM: Do we really need such a class?
@dataclass
class CaterpillarCert:
    key_id: bytes
    pub_key: ECC.EccKey


# AA: I think I want separate caterpillar public and private keys into two classes
#     private key could be a derivative class of public
# XM: The private cocoon is only used by the device to decrypt the certificate.
#     If we strictly follow the paper, we can use caterpillar+i instead. (Algorithm 4)
#     So every cocoon is public.

@dataclass
class Caterpillar:
    """Class for public cocoon keys"""
    key_id: bytes  # Derived name f_name(key_id, i)
    Bi: ECC.EccPoint
    #Qi: ECC.EccPoint

    class Encoding(enc.TlvModel):
        key_id = enc.BytesField(0xc1)
        b_der = enc.BytesField(0xc2)
        q_der = enc.BytesField(0xc3)

    def hatch(self) -> typing.Tuple[bytes, CaterpillarCert]:
        # Algorithm 3: CertCoalesce generation
        # XM: Need to sign the certificate, but this involves the application layer semantics
        #     Specifically the application namespace
        c = ECC.generate(curve=ECC_CURVE)
        a_i_c = ECC.EccKey(point=self.Bi+c.public_key().pointQ, curve=ECC_CURVE)
        c_bytes = c.export_key(format='DER', use_pkcs8=False)
        C = ECIES.encrypt(ECC.EccKey(point=self.P, curve=ECC_CURVE), c_bytes)
        return C, CaterpillarCert(key_id=self.key_id, pub_key=a_i_c)

    def encode_public(self) -> bytes:
        coc = Cocoon.Encoding()
        coc.key_id = self.key_id
        coc.b_der = ECC.EccKey(point=self.Bi, curve=ECC_CURVE).export_key(format='DER')
        coc.q_der = ECC.EccKey(point=self.Bi, curve=ECC_CURVE).export_key(format='DER')
        return coc.encode()

    @staticmethod
    def decode_public(extern_key: bytes):
        coc = Cocoon.Encoding.parse(extern_key)  # Raises ValueError, IndexError
        b_key = ECC.import_key(bytes(coc.b_der))
        q_key = ECC.import_key(bytes(coc.q_der))
        return EggKeys(key_id=bytes(coc.key_id), Bi=b_key.pointQ, Qi=q_key.pointQ)


## AA: is there way to remove hard-coding of XXXX in to_bytes(XXXX, ..) below. Looks error prone...
# XM: Switched to secrets.token_bytes(16)

@dataclass
class ButterflyKey:
    """Class for Butterfly keys"""
    key_id: bytes  # XM: Name Component is bytes; a full name will involve application-layer semantics
    a: int
    A: ECC.EccPoint
    p: int
    P: ECC.EccPoint
    ck: bytes
    #ek: bytes

    class Encoding(enc.TlvModel):
        key_id = enc.BytesField(0xb1)
        a_der = enc.BytesField(0xb2)
        p_der = enc.BytesField(0xb3)
        ck = enc.BytesField(0xb2)
        #ek = enc.BytesField(0xb3)

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

    def encode_private(self, passphrase: typing.Optional[str] = None) -> bytes:
        if self.a == 0 or self.p == 0:
            raise ValueError('Cannot encode private keys from a public caterpillar')
        cat = ButterflyKey.Encoding()
        cat.key_id = self.key_id
        cat.a_der = ECC.EccKey(d=self.a, curve=ECC_CURVE).export_key(format='DER', passphrase=passphrase)
        cat.p_der = ECC.EccKey(d=self.p, curve=ECC_CURVE).export_key(format='DER', passphrase=passphrase)
        cat.ck = self.ck
        return cat.encode()

    @staticmethod
    def decode_private(extern_key: bytes, passphrase: typing.Optional[str] = None):
        cat = ButterflyKey.Encoding.parse(extern_key)  # Raises ValueError, IndexError
        a_key = ECC.import_key(bytes(cat.a_der), passphrase)
        p_key = ECC.import_key(bytes(cat.p_der), passphrase)
        return ButterflyKey(key_id=bytes(cat.key_id),
                           a=int(a_key.d), A=a_key.pointQ,
                           p=int(p_key.d), P=p_key.pointQ,
                           ck=bytes(cat.ck))

    def encode_public(self) -> bytes:
        cat = ButterflyKey.Encoding()
        cat.key_id = self.key_id
        cat.a_der = ECC.EccKey(point=self.A, curve=ECC_CURVE).export_key(format='DER')
        cat.p_der = ECC.EccKey(point=self.P, curve=ECC_CURVE).export_key(format='DER')
        cat.ck = self.ck
        return cat.encode()

    @staticmethod
    def decode_public(extern_key: bytes):
        cat = ButterflyKey.Encoding.parse(extern_key)  # Raises ValueError, IndexError
        a_key = ECC.import_key(bytes(cat.a_der))
        p_key = ECC.import_key(bytes(cat.p_der))
        return ButterflyKey(key_id=bytes(cat.key_id),
                           a=0, A=a_key.pointQ,
                           p=0, P=p_key.pointQ,
                           ck=bytes(cat.ck))

    def to_public(self):
        # TODO deal with keyId
        return ButterflyKey(key_id=self.key_id, a=0, A=self.A, p=0, P=self.P, ck=self.ck)

    def layingEggkeys(self, i: int) -> Caterpillar:
        # Algorithm 2: Generate Cocoon Keys from public Caterpillar
        if i < 0 or i >= (1 << 64):
            raise ValueError(f'Input {i=} should be a 64-bit integer')
        return Caterpillar(key_id=f_name(self.key_id, i),
                      Bi=self.A + GEN_P256 * f_1(self.ck, i))

    def deriveCooconKeys(self, C: bytes, i: int) -> CocoonsKey:
        # Algorithm 4: Derive Butterfly Private Keys from encrypted C
        if i < 0 or i >= (1 << 64):
            raise ValueError(f'Input {i=} should be a 64-bit integer')
        #qi = (self.p + f_2(self.ek, i)) % SECP256R1_N
        c_bytes = ECIES.decrypt(ECC.EccKey(d=self.p, curve=ECC_CURVE), C)
        c = int(ECC.import_key(c_bytes).d)
        bi = (self.a + f_1(self.ck, i)) % SECP256R1_N
        bf_prv_key = (bi + c) % SECP256R1_N
        return CocoonsKey(key_id=f_name(self.key_id, i),
                            prv_key=ECC.EccKey(d=bf_prv_key, curve=ECC_CURVE))


    # def sign_key(self) -> bytes:
    #     prv_key = ECC.EccKey(d=self.a, curve=ECC_CURVE)
    #     return prv_key.export_key(format='DER', use_pkcs8=False)

    
    # def derive_cocoon(self, i: int = 0, j: int = 0) -> Cocoon:
    #     if i == 0:
    #         i = randint(0, (1 << 16) - 1)
    #     if j == 0:
    #         j = randint(0, 19)
    #     if self.a != 0 and self.h != 0:
    #         a_exp_prv, a_exp_pub = expand_key(i, j, self.ck, self.a, 'cert')
    #         h_exp_prv, h_exp_pub = expand_key(i, j, self.ek, self.h, 'enc')
    #     else:
    #         a_exp_prv, a_exp_pub = expand_key(i, j, self.ck, self.A, 'cert')
    #         h_exp_prv, h_exp_pub = expand_key(i, j, self.ek, self.H, 'enc')
    #     return Cocoon(i=i, j=j, a_exp_pub=a_exp_pub, h_exp_pub=h_exp_pub,
    #                   a_exp_prv=a_exp_prv, h_exp_prv=h_exp_prv)

    # def hatch(self) -> typing.Tuple[ECC.EccKey, ECC.EccKey]:
    #     r"""
    #     Generate a butterfly certificate.

    #     :return: a pair ``(c, bf)``.
    #     ``c`` is the private key used to generate the certificate,
    #     needed by the device to compute the butterfly private key.
    #     ``bf`` is the butterfly public key.
    #     """
    #     c_prv = ECC.generate(curve=ECC_CURVE)
    #     bf_pub = ECC.EccKey(point=self.a_exp_pub+c_prv.public_key().pointQ, curve=ECC_CURVE)
    #     return c_prv, bf_pub

    # def butterfly_prv(self, c_prv: ECC.EccKey) -> ECC.EccKey:
    #     r"""
    #     Derive the butterfly private key from received CA's private key.

    #     :param c_prv: the received private key from CA.
    #     :return: derived butterfly private key.
    #     """
    #     if self.a_exp_prv == 0:
    #         raise ValueError('The private cocoon key is required to derive the butterfly private key')
    #     return ECC.EccKey(d=(self.a_exp_prv + int(c_prv.d)) % SECP256R1_N, curve=ECC_CURVE)

    # def encrypt_key(self) -> ECC.EccKey:
    #     return ECC.EccKey(point=self.h_exp_pub, curve=ECC_CURVE)

    # def decrypt_key(self) -> ECC.EccKey:
    #     if self.h_exp_prv == 0:
    #         raise ValueError('The private cocoon key is required to get the decrypt key')
    #     return ECC.EccKey(d=self.h_exp_prv, curve=ECC_CURVE)
