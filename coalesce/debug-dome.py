# ButterflyKeys logic
# Use Pycryptodome only

import secrets
import typing
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from Cryptodome.Protocol.KDF import HKDF

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


def randint(inclusive_lower_bound: int, exclusive_upper_bound: int) -> int:
    return (inclusive_lower_bound +
            secrets.randbelow(exclusive_upper_bound - inclusive_lower_bound))


def ecies_encrypt(pub_key: ECC.EccKey, content: bytes) -> bytes:
    # ephemeral key
    ek = ECC.generate(curve='secp256r1')
    # ek.d * pub_key.Q = ek.public_key.Q * pri_key.d
    p = pub_key.pointQ * ek.d
    p_bytes = int(p.x).to_bytes(32, 'big') + int(p.y).to_bytes(32, 'big')
    ek_q = ek.public_key().pointQ
    ek_q_bytes = int(ek_q.x).to_bytes(32, 'big') + int(ek_q.y).to_bytes(32, 'big')
    master = ek_q_bytes + p_bytes
    derived = HKDF(master, 32, b'', SHA256)
    cipher = AES.new(derived, AES.MODE_GCM)

    encrypted, tag = cipher.encrypt_and_digest(content)
    ret = bytearray()
    ret.extend(ek_q_bytes)
    ret.extend(cipher.nonce)
    ret.extend(tag)
    ret.extend(encrypted)
    return bytes(ret)


def ecies_decrypt(pri_key: ECC.EccKey, cipher_text: bytes) -> bytes:
    ek_q_bytes = cipher_text[0:64]
    nonce = cipher_text[64:80]
    tag = cipher_text[80:96]
    encrypted = cipher_text[96:]

    # ephemeral key
    ek_q = ECC.EccPoint(x=int.from_bytes(ek_q_bytes[:32], 'big'),
                        y=int.from_bytes(ek_q_bytes[32:], 'big'),
                        curve='secp256r1')
    # ek.d * pub_key.Q = ek.public_key.Q * pri_key.d
    p = ek_q * pri_key.d
    p_bytes = int(p.x).to_bytes(32, 'big') + int(p.y).to_bytes(32, 'big')
    master = ek_q_bytes + p_bytes
    derived = HKDF(master, 32, b'', SHA256)
    cipher = AES.new(derived, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(encrypted, tag)


def main():
    # Generate parameter
    a = randint(1, SECP256R1_N - 1)
    h = randint(1, SECP256R1_N - 1)
    ck = secrets.randbits(128).to_bytes(16, 'big')
    ek = secrets.randbits(128).to_bytes(16, 'big')
    i = randint(0, (1 << 16) - 1)
    j = randint(0, 19)

    print('Expanding Certificate key pair (a,A)')
    print('------------------------------------')

    a_exp, A_exp = bfexpandkey(i, j, ck, a, 'cert')
    assert GEN_P256 * a_exp == A_exp, "error in certificate key expansion"

    def print_key_pair(text, d, q):
        print(f'{text} private key (256 bits):')
        print(f'0x{d.to_bytes(32, "big").hex()}')
        print(f'Expanded public key (256 bits):')
        print(f'[0x{int(q.x).to_bytes(32, "big").hex()}, 0x{int(q.y).to_bytes(32, "big").hex()}]')
        print()

    print_key_pair('Expanded', a_exp, A_exp)

    print("SUCCESS: Verified that expanded certificate private and public keys form a key pair")
    print()

    print("Expanding Encryption key pair (h,H)")
    print("-----------------------------------")

    h_exp, H_exp = bfexpandkey(i, j, ek, h, 'enc')
    assert GEN_P256 * h_exp == H_exp, "error in encryption key expansion"

    print_key_pair('Expanded', h_exp, H_exp)

    print("SUCCESS: Verified that expanded encryption private and public keys form a key pair")
    print()

    print("Generating Butterfly certificates")
    print("---------------------------------")

    # CA generates certificate
    c_prv = ECC.generate(curve='secp256r1')
    c = int(c_prv.d)
    C = c_prv.public_key().pointQ
    bf_pub = A_exp + C
    # response = c || certificate(bf_pub)
    response = c.to_bytes(32, 'big') + int(bf_pub.x).to_bytes(32, 'big') + int(bf_pub.y).to_bytes(32, 'big')
    res_enc = ecies_encrypt(ECC.EccKey(point=H_exp, curve='secp256r1'), response)

    # Device decrypts CA's response and get certificate
    res_dec = ecies_decrypt(ECC.EccKey(d=h_exp, curve='secp256r1'), res_enc)
    assert res_dec == response, "error in ecies encryption"
    recved_c = int.from_bytes(res_dec[0:32], 'big')
    assert recved_c == c, "error in ecies encryption"
    # In this demo we use public key directly to represent certificate
    recved_cert = res_dec[32:]
    assert recved_cert == int(bf_pub.x).to_bytes(32, 'big') + int(bf_pub.y).to_bytes(32, 'big')
    bf_prv = (a_exp + c) % SECP256R1_N

    print_key_pair('Generated butterfly', bf_prv, bf_pub)

    # Verify bf_pri and bf_pub are paired ECC keys
    final_prv_key = ECC.EccKey(d=bf_prv, curve='secp256r1')
    final_pub_key = ECC.EccKey(point=bf_pub, curve='secp256r1')
    test_msg = '''Lorem ipsum dolor sit amet,
    consectetur adipiscing elit,
    sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
    Ut enim ad minim veniam,
    quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.
    Duis aute irure dolor in reprehenderit in voluptate
    velit esse cillum dolore eu fugiat nulla pariatur.
    Excepteur sint occaecat cupidatat non proident,
    sunt in culpa qui officia deserunt mollit anim id est laborum.
    '''.encode('utf-8')
    msg_hash = SHA256.new(test_msg)
    signature = DSS.new(final_prv_key, 'fips-186-3', 'der').sign(msg_hash)
    DSS.new(final_pub_key, 'fips-186-3', 'der').verify(msg_hash, signature)

    print("SUCCESS: Verified that generated butterfly private and public keys are paired")


if __name__ == "__main__":
    main()
