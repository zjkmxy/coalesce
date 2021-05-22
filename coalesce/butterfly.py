import typing
import secrets
from dataclasses import dataclass
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import ECC


# Recommended Elliptic Curve Domain Parameters
ECC_CURVE = 'secp256r1'
SECP256R1_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
SECP256R1_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
SECP256R1_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
GEN_P256 = ECC.EccPoint(x=SECP256R1_GX, y=SECP256R1_GY, curve=ECC_CURVE)


def randint(inclusive_lower_bound: int, exclusive_upper_bound: int) -> int:
    return (inclusive_lower_bound +
            secrets.randbelow(exclusive_upper_bound - inclusive_lower_bound))


def f_k_int_x(k: bytes, x: int) -> bytes:
    r"""
    f_k^{int}(x) = (AES(k, x+1) XOR (x+1)) || (AES(k, x+2) XOR (x+2)) || (AES(k, x+3) XOR (x+3))

    :param k: the AES key (128-bit).
    :param x: the input block (128-bit).
    :return: the big-endian integer representation of f_k^{int}(x)
    """
    aes_obj = AES.new(k, AES.MODE_ECB)
    ret = [b'', b'', b'']
    for i in range(1, 4):
        xpi = (x + i).to_bytes(16, 'big')
        aes_xpi = aes_obj.encrypt(xpi)
        blki_int = int.from_bytes(xpi, 'big') ^ int.from_bytes(aes_xpi, 'big')
        ret[i-1] = blki_int.to_bytes(16, 'big')

    return b''.join(ret)


def expand_key(i: int, j: int, exp: bytes,
               seed: typing.Union[int, ECC.EccPoint],
               exp_type: str = 'cert') -> typing.Tuple[int, ECC.EccPoint]:
    r"""
    Butterfly expansion for 'cert' and 'enc' keys

    :param i: the ``i`` value for the corresponding certificate
    :param j: the ``j`` value for the corresponding certificate
    :param exp: expansion value. An AES key (128-bit).
    :param seed: the seed key, can be either private (1~SECP256R1_N-1) or public (EccPoint).
    :param exp_type: the type of key expansion. "cert" (default) or "enc"
    :return: a pair ``(pri, pub)`` of the private (if possible) and public key,
        If ``seed`` is a private key, ``GEN_P256 * pri == pub``.
        If ``seed`` is a public key, ``pri == 0``.
    """
    if exp_type == 'cert':
        p0 = 0
    elif exp_type == 'enc':
        p0 = (1 << 32) - 1
    else:
        raise ValueError(f'Unsupported expansion type: {exp_type}')

    # x is the input to the expansion function
    # 0^{32} || i || j || 0^{32}  for certificate
    # 1^{32} || i || j || 0^{32}  for encryption key
    x = (p0 << 96) | (i << 64) | (j << 32) | 0
    f_k_x = int.from_bytes(f_k_int_x(exp, x), 'big') % SECP256R1_N

    if isinstance(seed, int):
        prv = (seed + f_k_x) % SECP256R1_N
        seed_pub = GEN_P256 * seed
        pub = seed_pub + GEN_P256 * f_k_x
    elif isinstance(seed, ECC.EccPoint):
        prv = 0
        pub = seed + GEN_P256 * f_k_x
    else:
        raise ValueError(f'Unsupported seed type: {seed}')

    return prv, pub


@dataclass
class Cocoon:
    """Class for cocoon keys"""
    i: int
    j: int
    a_exp_pub: ECC.EccPoint
    h_exp_pub: ECC.EccPoint
    a_exp_prv: int = 0
    h_exp_prv: int = 0

    def hatch(self) -> typing.Tuple[ECC.EccKey, ECC.EccKey]:
        r"""
        Generate a butterfly certificate.

        :return: a pair ``(c, bf)``.
        ``c`` is the private key used to generate the certificate,
        needed by the device to compute the butterfly private key.
        ``bf`` is the butterfly public key.
        """
        c_prv = ECC.generate(curve=ECC_CURVE)
        bf_pub = ECC.EccKey(point=self.a_exp_pub+c_prv.public_key().pointQ, curve=ECC_CURVE)
        return c_prv, bf_pub

    def butterfly_prv(self, c_prv: ECC.EccKey) -> ECC.EccKey:
        r"""
        Derive the butterfly private key from received CA's private key.

        :param c_prv: the received private key from CA.
        :return: derived butterfly private key.
        """
        if self.a_exp_prv == 0:
            raise ValueError('The private cocoon key is required to derive the butterfly private key')
        return ECC.EccKey(d=(self.a_exp_prv + int(c_prv.d)) % SECP256R1_N, curve=ECC_CURVE)

    def encrypt_key(self) -> ECC.EccKey:
        return ECC.EccKey(point=self.h_exp_pub, curve=ECC_CURVE)

    def decrypt_key(self) -> ECC.EccKey:
        if self.h_exp_prv == 0:
            raise ValueError('The private cocoon key is required to get the decrypt key')
        return ECC.EccKey(d=self.h_exp_prv, curve=ECC_CURVE)


@dataclass
class Caterpillar:
    """Class for caterpillar keys"""
    A: ECC.EccPoint
    H: ECC.EccPoint
    ck: bytes = b''
    ek: bytes = b''
    a: int = 0
    h: int = 0

    @staticmethod
    def generate():
        a = randint(1, SECP256R1_N - 1)
        h = randint(1, SECP256R1_N - 1)
        ck = secrets.randbits(128).to_bytes(16, 'big')
        ek = secrets.randbits(128).to_bytes(16, 'big')
        return Caterpillar(A=GEN_P256*a, H=GEN_P256*h, ck=ck, ek=ek, a=a, h=h)

    def save_prv(self) -> bytes:
        # Should we use PKCS?
        return b''.join([self.a.to_bytes(32, 'big'), self.h.to_bytes(32, 'big'), self.ck, self.ek])

    @staticmethod
    def load_prv(extern_key: bytes):
        a = int.from_bytes(extern_key[0:32], 'big')
        h = int.from_bytes(extern_key[32:64], 'big')
        ek = extern_key[80:96]
        ck = extern_key[64:80]
        return Caterpillar(A=GEN_P256*a, H=GEN_P256*h, ck=ck, ek=ek, a=a, h=h)

    def export_pub(self) -> bytes:
        return b''.join([int(self.A.x).to_bytes(32, 'big'), int(self.A.y).to_bytes(32, 'big'),
                         int(self.H.x).to_bytes(32, 'big'), int(self.H.y).to_bytes(32, 'big'),
                         self.ck, self.ek])

    @staticmethod
    def import_pub(extern_key: bytes):
        ax = int.from_bytes(extern_key[0:32], 'big')
        ay = int.from_bytes(extern_key[32:64], 'big')
        hx = int.from_bytes(extern_key[64:96], 'big')
        hy = int.from_bytes(extern_key[96:128], 'big')
        ck = extern_key[128:144]
        ek = extern_key[144:160]
        return Caterpillar(A=ECC.EccPoint(x=ax, y=ay, curve=ECC_CURVE),
                           H=ECC.EccPoint(x=hx, y=hy, curve=ECC_CURVE),
                           ck=ck, ek=ek, a=0, h=0)

    def public_key(self):
        return Caterpillar(A=self.A, H=self.H, ck=self.ck, ek=self.ek, a=0, h=0)

    def derive_cocoon(self, i: int = 0, j: int = 0) -> Cocoon:
        if i == 0:
            i = randint(0, (1 << 16) - 1)
        if j == 0:
            j = randint(0, 19)
        if self.a != 0 and self.h != 0:
            a_exp_prv, a_exp_pub = expand_key(i, j, self.ck, self.a, 'cert')
            h_exp_prv, h_exp_pub = expand_key(i, j, self.ek, self.h, 'enc')
        else:
            a_exp_prv, a_exp_pub = expand_key(i, j, self.ck, self.A, 'cert')
            h_exp_prv, h_exp_pub = expand_key(i, j, self.ek, self.H, 'enc')
        return Cocoon(i=i, j=j, a_exp_pub=a_exp_pub, h_exp_pub=h_exp_pub,
                      a_exp_prv=a_exp_prv, h_exp_prv=h_exp_prv)

    def sign_key(self) -> str:
        prv_key = ECC.EccKey(d=self.a, curve=ECC_CURVE)
        return prv_key.export_key(format='DER', use_pkcs8=False)
