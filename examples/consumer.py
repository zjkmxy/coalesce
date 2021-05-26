import logging
import time

import ndn.utils
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from ndn.app import NDNApp
from ndn.types import InterestNack, InterestTimeout, InterestCanceled, ValidationFailure
from ndn.encoding import Name, Component, InterestParam, parse_data
from ndn.app_support import security_v2 as ndnsec
from coalesce.utils import ecc_checker
from Cryptodome.PublicKey import ECC


CA_NAME = '/coal-exam/CA/example-ca'
ROLE_NAMES = [Name.from_str('/coal-exam/ROLE/role1'),
              Name.from_str('/coal-exam/ROLE/role2')]
DATA_NAMES = [Name.from_str('/coal-exam/scope1/testApp'),
              Name.from_str('/coal-exam/scope2/testApp')]


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')


app = NDNApp()


async def main():
    # Fetch CA's public key for demonstration.
    # Pre-shared in real-world scenario
    _, _, ca_pub_key = await app.express_interest(CA_NAME + '/KEY', can_be_prefix=True)
    ca_pub_key = bytes(ca_pub_key)

    async def request_data(k):
        timestamp = ndn.utils.timestamp()
        name = DATA_NAMES[k] + [Component.from_timestamp(timestamp)]
        print(f'Sending Interest {Name.to_str(name)}, {InterestParam(must_be_fresh=True, lifetime=6000)}')
        data_name, meta_info, content, raw = await app.express_interest(
            name, must_be_fresh=True, can_be_prefix=False, lifetime=6000,
            need_raw_packet=True)

        print(f'Received Data Name: {Name.to_str(data_name)}')
        print(meta_info)
        print(bytes(content) if content else None)

        _, _, _, sig_ptrs = parse_data(raw, with_tl=True)
        key_name = sig_ptrs.signature_info.key_locator.name

        if Name.is_prefix(ROLE_NAMES[k], key_name):
            print(f'Signing key {Name.to_str(key_name)} belongs to role {Name.to_str(ROLE_NAMES[k])}')
        else:
            print(f'ERROR: Signing key {Name.to_str(key_name)} does NOT belong to role {Name.to_str(ROLE_NAMES[k])}')
            exit(1)

        try:
            _, _, _, raw = await app.express_interest(
                key_name, must_be_fresh=True, can_be_prefix=True, lifetime=6000,
                need_raw_packet=True, validator=ecc_checker(ECC.import_key(ca_pub_key)))
        except (InterestNack, InterestTimeout, InterestNack, ValidationFailure) as e:
            print(f'ERROR: Unable to fetch certificate due to {e}')
            exit(2)

        print(f'Certificate Received')
        cert = ndnsec.parse_certificate(raw)
        pub_key = ECC.import_key(bytes(cert.content))
        verifier = DSS.new(pub_key, 'fips-186-3', 'der')
        h = SHA256.new()
        for content in sig_ptrs.signature_covered_part:
            h.update(content)
        verifier.verify(h, bytes(sig_ptrs.signature_value_buf))
        print(f'Signature validated')

        not_before = bytes(cert.signature_info.validity_period.not_before).decode('utf-8')
        not_after = bytes(cert.signature_info.validity_period.not_after).decode('utf-8')
        print(f'Certificate is valid from {not_before} to {not_after}')
        print(f'Now is {time.strftime("%Y%m%dT%H%M%S", time.gmtime())}')
        print()

    for i in range(len(DATA_NAMES)):
        await request_data(i)

    app.shutdown()


if __name__ == '__main__':
    app.run_forever(after_start=main())
