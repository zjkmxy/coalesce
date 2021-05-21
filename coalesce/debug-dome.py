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
    r"""
    f_k^{int}(x) = (AES(k, x+1) XOR (x+1)) || (AES(k, x+2) XOR (x+2)) || (AES(k, x+3) XOR (x+3))

    :param k: the AES key (128-bit).
    :type k: bytes
    :param x: the input block (128-bit).
    :type x: int
    :return: the big-endian integer representation of f_k^{int}(x)
    :rtype: bytes
    """
    aes_obj = AES.new(k, AES.MODE_ECB)
    ret = [b'', b'', b'']
    for i in range(1, 4):
        xpi = (x + i).to_bytes(16, 'big')
        aes_xpi = aes_obj.encrypt(xpi)
        blki_int = int.from_bytes(xpi, 'big') ^ int.from_bytes(aes_xpi, 'big')
        ret[i-1] = blki_int.to_bytes(16, 'big')

    return b''.join(ret)


def bfexpandkey(i: int, j: int, exp: bytes, seed_prv: int, exp_type: str = 'cert') -> typing.Tuple[int, ECC.EccPoint]:
    r"""
    Butterfly expansion for 'cert' and 'enc' keys

    :param i: the ``i`` value for the corresponding certificate
    :type i: int
    :param j: the ``j`` value for the corresponding certificate
    :type j: int
    :param exp: expansion value. An AES key (128-bit).
    :type exp: bytes
    :param seed_prv: the seed private key (1~SECP256R1_N-1).
    :type seed_prv: int
    :param exp_type: the type of key expansion. "cert" (default) or "enc"
    :type exp_type: str
    :return: a pair ``(pri, pub)`` of the private and the public key,
        satisfying ``GEN_P256 * pri == pub``.
    :rtype: (int, ECC.EccPoint)
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

    print('Expanding Certificate key pair (a,A)')
    print('------------------------------------')

    a_exp, A_exp = bfexpandkey(i, j, ck, a, 'cert')
    assert GEN_P256 * a_exp == A_exp, "error in certificate key expansion"

    print(f'Expanded private key (256 bits):')
    print(f'0x{a_exp.to_bytes(32, "big")}')
    print(f'Expanded public key (256 bits):')
    print(f'[0x{int(A_exp.x).to_bytes(32, "big")}, 0x{int(A_exp.y).to_bytes(32, "big")}]')
    print()

    print("SUCCESS: Verified that expanded certificate private and public keys form a key pair")
    print()

    print("Expanding Encryption key pair (h,H)")
    print("-----------------------------------")

    h_exp, H_exp = bfexpandkey(i, j, ek, h, 'enc')
    assert GEN_P256 * h_exp == H_exp, "error in encryption key expansion"

    print(f'Expanded private key (256 bits):')
    print(f'0x{h_exp.to_bytes(32, "big")}')
    print(f'Expanded public key (256 bits):')
    print(f'[0x{int(H_exp.x).to_bytes(32, "big")}, 0x{int(H_exp.y).to_bytes(32, "big")}]')
    print()

    print("SUCCESS: Verified that expanded encryption private and public keys form a key pair")
    print()


if __name__ == "__main__":
    main()
