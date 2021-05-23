import secrets
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import ECC
from ndn.encoding import Component

# Recommended Elliptic Curve Domain Parameters
# (from reference: https://stash.campllc.org/projects/SCMS/repos/crypto-test-vectors/browse)
ECC_CURVE = 'secp256r1'
SECP256R1_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
# SECP256R1_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
# SECP256R1_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
# GEN_P256 = ECC.EccPoint(x=SECP256R1_GX, y=SECP256R1_GY, curve=ECC_CURVE)

AES_KEY_BYTES = 16
AES_KEY_BITS = 1 << AES_KEY_BYTES


def randint(inclusive_lower_bound: int, exclusive_upper_bound: int) -> int:
    return (inclusive_lower_bound +
            secrets.randbelow(exclusive_upper_bound - inclusive_lower_bound))


def f_1(exp: bytes, i: int):
    j = i & ((1 << 64) - 1)
    x = j << 32
    aes_obj = AES.new(exp, AES.MODE_ECB)
    ret = [0, 0, 0]
    for i in range(1, 4):
        xpi = (x + i).to_bytes(AES_KEY_BYTES, 'big')
        aes_xpi = aes_obj.encrypt(xpi)
        ret[i - 1] = int.from_bytes(xpi, 'big') ^ int.from_bytes(aes_xpi, 'big')

    return ((ret[0] << AES_KEY_BITS << AES_KEY_BITS) | (ret[1] << AES_KEY_BITS) | ret[2]) % SECP256R1_N


def f_name(key_id: bytes, i: int) -> bytes:
    # need to figure out NDN name derivation function
    ret = bytes(Component.get_value(key_id)) + f'-{i}'.encode()
    return Component.from_bytes(ret)

