import typing
from coalesce.butterfly import MasterKey
from ndn import encoding as enc
from ndn.encoding import Name, Component, SignaturePtrs
from ndn.security import DigestSha256Signer, Sha256WithEcdsaSigner
from ndn.app_support import security_v2 as ndnsec
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from coalesce.utils import derive_cert


N = 6
pib_dict = []
prv_keys = []


def get_validator(i):
    def validator(_name, sig_ptrs: SignaturePtrs):
        # key_name = sig_ptrs.signature_info.key_locator.name
        cert_bytes = pib_dict[i]
        if cert_bytes is None:
            return False
        try:
            cert = ndnsec.parse_certificate(cert_bytes)
        except (ValueError, IndexError):
            return False
        pub_key = ECC.import_key(bytes(cert.content))
        verifier = DSS.new(pub_key, 'fips-186-3', 'der')
        h = SHA256.new()
        for content in sig_ptrs.signature_covered_part:
            h.update(content)
        try:
            verifier.verify(h, bytes(sig_ptrs.signature_value_buf))
            return True
        except ValueError:
            return False

    return validator


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def gen_cert(name_prefix, key_id, pub_key, signer):
    # Derive cocoon certificate
    public_key_der = bytes(pub_key.export_key(format='DER'))
    cert_name, cert = derive_cert(name_prefix + [key_id], b'coalesce', public_key_der, signer, 10000)
    return cert_name, cert


def ca_process(butterfly_pub: MasterKey, i_set: typing.List[int]) -> bytes:
    print(f'CA:\tReceived public butterfly')
    # Generate kaleidoscope identity 'c'
    butterfly_pub.random_pick_c()
    print(f'CA:\tGenerated kaleidoscope {int(butterfly_pub.c.d).to_bytes(32, "big").hex()[:16]}')

    cert_names = []
    certs = []
    
    for i in i_set:
        cat = butterfly_pub.derive_public_key(Name.to_bytes('/coalesce/KEY'), i)
        print(f'CA:\tLaid egg for i={i}.')
        # Generate caterpillar certificates per i
        cert_name, cert = gen_cert(Name.from_str('/coalesce/KEY'), Component.from_str(f'demo-{i}'),
                                   cat, DigestSha256Signer())
        cert_names.append(cert_name)
        certs.append(cert)
    print()

    input("...")

    # Lay one egg & caterpillar per i
    for i in i_set:
        print(f'CA:\tDerived certificate: {Name.to_str(cert_names[i-1])}.')
        pib_dict.append(certs[i-1])

    print()

    input("...")

    # Return encrypted kaleidoscope identity 'c' to the client
    kaleidoscope_encrypted = butterfly_pub.encrypt_c()
    print(f'CA:\tReturn encrypted kaleidoscope: {kaleidoscope_encrypted.hex()[:16]}')

    print()

    input("...")

    return kaleidoscope_encrypted


def device_process():
    # Generate a new butterfly
    butterfly = MasterKey.generate()
    tmp = Name.from_str('/coalesce/KEY')
    tmp.append(Component.from_str('demo'))
    print(f'DEVICE:\tGenerated new butterfly ', Name.to_str(tmp))
    print()

    input("...")
    
    # Derive public butterfly
    bf_pub = butterfly.to_public()
    # Send public butterfly and a set of i to CA
    i_set = list(range(1, N + 1))
    print(f'DEVICE:\tSend public butterfly and i set {i_set} to CA.')
    print()

    input("...")

    kaleidoscope_encrypted = ca_process(bf_pub, i_set)
    print()
    print(f'DEVICE:\tReceived encrypted kaleidoscope: {kaleidoscope_encrypted.hex()[:16]}')
    # Decode kaleidoscope identity 'c'
    butterfly.decrypt_c(kaleidoscope_encrypted)
    print(f'DEVICE:\tDecrypted kaleidoscope: {int(butterfly.c.d).to_bytes(32, "big").hex()[:16]}')

    print()

    input("...")

    # Derive cocoon private keys
    for i in i_set:
        prv_keys.append(butterfly.derive_private_key(Name.to_bytes('/coalesce/KEY'), i))
        key_name = Name.from_str('/coalesce/KEY') + [Component.from_str(f'demo-{i}')]
        print(f'DEVICE:\tAdded private key {Name.to_str(key_name)}')
    print()

    input("...")


def validation_process():
    packets = []
    # Sign n packets
    print('Signing packets ...')
    for i in range(len(prv_keys)):
        key_bits = prv_keys[i].export_key(format='DER', use_pkcs8=False)
        key_name = Name.from_str('/coalesce/KEY') + [Component.from_str(f'demo-{i}')]
        signer = Sha256WithEcdsaSigner(key_name, key_bits)
        data = enc.make_data(f'/temp-data/{i}',
                             enc.MetaInfo(freshness_period=10000),
                             b'Hello World!',
                             signer)
        packets.append(data)
        print(f'Signed with key {Name.to_str(key_name)}')
    print()

    # Cross validate the signatures
    print('Cross validating the signatures ...')
    for i, data in enumerate(packets):
        for j in range(len(prv_keys)):
            validator = get_validator(j)
            name, _, _, sig_ptrs = enc.parse_data(data)
            if validator(name, sig_ptrs):
                print(f'{bcolors.OKGREEN}O{bcolors.ENDC}', end='')
            else:
                print(f'{bcolors.FAIL}X{bcolors.ENDC}', end='')
        print()


if __name__ == '__main__':
    device_process()
    validation_process()
