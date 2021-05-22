import logging
import ndn.utils
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from ndn.app import NDNApp
from ndn.types import InterestNack, InterestTimeout, InterestCanceled, ValidationFailure
from ndn.encoding import Name, Component, InterestParam, parse_data
from ndn.app_support import security_v2 as ndnsec


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')


app = NDNApp()


async def main():
    timestamp = ndn.utils.timestamp()
    name = Name.from_str('/example-device/testApp/randomData') + [Component.from_timestamp(timestamp)]
    print(f'Sending Interest {Name.to_str(name)}, {InterestParam(must_be_fresh=True, lifetime=6000)}')
    data_name, meta_info, content, raw = await app.express_interest(
        name, must_be_fresh=True, can_be_prefix=False, lifetime=6000,
        need_raw_packet=True)

    print(f'Received Data Name: {Name.to_str(data_name)}')
    print(meta_info)
    print(bytes(content) if content else None)

    _, _, _, sig_ptrs = parse_data(raw, with_tl=True)
    key_name = sig_ptrs.signature_info.key_locator.name
    print(f'Fetching Key {Name.to_str(key_name)}')
    _, _, _, raw = await app.express_interest(
        key_name, must_be_fresh=True, can_be_prefix=True, lifetime=6000,
        need_raw_packet=True)

    print(f'Certificate Received')
    cert = ndnsec.parse_certificate(raw)
    pub_key = ECC.import_key(bytes(cert.content))
    verifier = DSS.new(pub_key, 'fips-186-3', 'der')
    h = SHA256.new()
    for content in sig_ptrs.signature_covered_part:
        h.update(content)
    verifier.verify(h, bytes(sig_ptrs.signature_value_buf))

    print(f'Signature validated')

    app.shutdown()


if __name__ == '__main__':
    app.run_forever(after_start=main())
