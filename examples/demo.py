import typing
from coalesce.butterfly import ButterflyKey
from ndn import encoding as enc
from ndn.encoding import Name, Component, SignaturePtrs
from ndn.security import DigestSha256Signer, Sha256WithEcdsaSigner
from ndn.app_support import security_v2 as ndnsec
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS


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


def ca_process(butterfly_pub: ButterflyKey, i_set: typing.List[int]) -> bytes:
    print(f'CA:\tReceived public butterfly')
    # Generate kaleidoscope identity 'c'
    butterfly_pub.gen_kaleidoscope()
    print(f'CA:\tGenerated kaleidoscope {int(butterfly_pub.c.d).to_bytes(32, "big").hex()[:16]}')
    # Lay one egg & caterpillar per i
    for i in i_set:
        cat = butterfly_pub.lay_egg(i)
        print(f'CA:\tLaid egg for i={i}.')
        # Generate caterpillar certificates per i
        cert_name, cert = cat.derive_cert(Name.from_str('/coalesce/KEY'), DigestSha256Signer(), 10000)
        print(f'CA:\tDerived certificate: {Name.to_str(cert_name)}.')
        pib_dict.append(cert)
    # Return encrypted kaleidoscope identity 'c' to the client
    kaleidoscope_encrypted = butterfly_pub.encrypt_kaleidoscope()
    print(f'CA:\tReturned with encrypted kaleidoscope: {kaleidoscope_encrypted.hex()[:16]}')
    return kaleidoscope_encrypted


def device_process():
    # Generate a new butterfly
    butterfly = ButterflyKey.generate(Component.from_str('demo'))
    print(f'DEVICE:\tGenerated new butterfly.')
    # Derive public butterfly
    bf_pub = butterfly.to_public()
    # Send public butterfly and a set of i to CA
    i_set = list(range(1, N + 1))
    print(f'DEVICE:\tSend public butterfly and i set {i_set} to CA.')
    print()
    kaleidoscope_encrypted = ca_process(bf_pub, i_set)
    print()
    print(f'DEVICE:\tReceived encrypted kaleidoscope: {kaleidoscope_encrypted.hex()[:16]}')
    # Decode kaleidoscope identity 'c'
    butterfly.decrypt_kaleidoscope(kaleidoscope_encrypted)
    print(f'DEVICE:\tDecrypted kaleidoscope: {int(butterfly.c.d).to_bytes(32, "big").hex()[:16]}')
    # Derive cocoon private keys
    for i in i_set:
        prv_keys.append(butterfly.pupate_cocoon_key(i))
        key_name = Name.from_str('/coalesce/KEY') + [prv_keys[-1].key_id]
        print(f'DEVICE:\tAdded private key {Name.to_str(key_name)}')
    print()


def validation_process():
    packets = []
    # Sign n packets
    print('Signing packets ...')
    for i in range(len(prv_keys)):
        key_bits = prv_keys[i].prv_key.export_key(format='DER', use_pkcs8=False)
        key_name = Name.from_str('/coalesce/KEY') + [prv_keys[i].key_id]
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
