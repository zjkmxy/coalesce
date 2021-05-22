# ButterflyKeys logic
# Use Pycryptodome only

import secrets
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
import butterfly
import ECIES
from butterfly import SECP256R1_N, GEN_P256


def randint(inclusive_lower_bound: int, exclusive_upper_bound: int) -> int:
    return (inclusive_lower_bound +
            secrets.randbelow(exclusive_upper_bound - inclusive_lower_bound))


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

    a_exp, A_exp = butterfly.expand_key(i, j, ck, a, 'cert')
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

    h_exp, H_exp = butterfly.expand_key(i, j, ek, h, 'enc')
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
    res_enc = ECIES.encrypt(ECC.EccKey(point=H_exp, curve='secp256r1'), response)

    # Device decrypts CA's response and get certificate
    res_dec = ECIES.decrypt(ECC.EccKey(d=h_exp, curve='secp256r1'), res_enc)
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
