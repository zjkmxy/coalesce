# ButterflyKeys logic
# Use Pycryptodome only

import random
import typing
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import ECC

# Recommended Elliptic Curve Domain Parameters
SECP256R1_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
SECP256R1_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
SECP256R1_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
GEN_P256 = ECC.EccPoint(x=SECP256R1_GX, y=SECP256R1_GY, curve='secp256r1')


def f_k_int_x(k: bytes, x: int) -> bytes:
    """
    f_k^{int}(x)
    """
    aes_obj = AES.new(k, AES.MODE_ECB)
    s = b''
    for i in range(1, 4):
        xpi = (x + i).to_bytes(16, 'big')
        aes_xpi = aes_obj.encrypt(xpi)
        blki_int = int.from_bytes(xpi, 'big') ^ int.from_bytes(aes_xpi, 'big')
        blki = blki_int.to_bytes(16, 'big')
        s += blki

    return s


def bfexpandkey(i: int, j: int, exp: bytes, seed_prv: int, exp_type: str = "cert") -> typing.Tuple[int, ECC.EccPoint]:
    if exp_type == 'cert':
        p0 = 0
    elif exp_type == 'enc':
        p0 = (1 << 32) - 1
    else:
        raise ValueError(f'Unsupported expansion type: {exp_type}')

    # x = 0/1 || i || j || 0 is the input to the expansion function
    x = (p0 << 96) | (i << 64) | (j << 32) | 0
    f_k_x = int.from_bytes(f_k_int_x(exp, x), 'big') % SECP256R1_N

    prv = (seed_prv + f_k_x) % SECP256R1_N
    seed_pub = GEN_P256 * seed_prv
    pub = seed_pub + GEN_P256 * f_k_x

    return prv, pub


def main():
    random.seed(333)

    # Generate parameter
    a = random.randint(1, SECP256R1_N - 1)
    h = random.randint(1, SECP256R1_N - 1)
    ck = random.getrandbits(128).to_bytes(16, 'big')
    ek = random.getrandbits(128).to_bytes(16, 'big')
    i = random.randint(0, (1 << 16) - 1)
    j = random.randint(0, 19)

    # Get points
    # A = GEN_P256 * a
    # H = GEN_P256 * h

    # x_cert = (i * radix_32 + j) * radix_32
    # x_enc = (((radix_32 - 1) * radix_32 + i) * radix_32 + j) * radix_32

    # f_k_int_x_cert = f_k_int_x(ck, x_cert)
    # f_k_x_cert = int.from_bytes(f_k_int_x_cert, 'big') % SECP256R1_N

    print("Expanding Certificate key pair (a,A)")
    print("------------------------------------")

    # Expanded private and public keys for a
    # a_exp = (a + f_k_x_cert) % SECP256R1_N
    # A_exp = A + GEN_P256 * f_k_x_cert
    a_exp, A_exp = bfexpandkey(i, j, ck, a, 'cert')

    assert GEN_P256 * a_exp == A_exp, "error in certificate key expansion"
    print("SUCCESS: Verified that expanded certificate private and public keys form a key pair")
    print()

    print("Expanding Encryption key pair (h,H)")
    print("-----------------------------------")

    # f_k_int_x_enc = f_k_int_x(ek, x_enc)
    # f_k_x_enc = int.from_bytes(f_k_int_x_enc, 'big') % SECP256R1_N

    # Expanded private and public keys for h
    # h_exp = (h + f_k_x_enc) % SECP256R1_N
    # H_exp = H + GEN_P256 * f_k_x_enc
    h_exp, H_exp = bfexpandkey(i, j, ek, h, 'enc')

    assert GEN_P256 * h_exp == H_exp, "error in encryption key expansion"
    print("SUCCESS: Verified that expanded encryption private and public keys form a key pair")
    print()


if __name__ == "__main__":
    main()
