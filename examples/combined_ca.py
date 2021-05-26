import logging
import asyncio as aio
from Cryptodome.PublicKey import ECC
from ndn.encoding import Name
from ndn.app import NDNApp
from ndn.security import Sha256WithEcdsaSigner
from ndn.app_support import security_v2 as ndnsec
from coalesce.coalesce_v1 import CaServer


CA_PRV_KEY = ('-----BEGIN EC PRIVATE KEY-----\n'
              'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQokyv+7mV17S4P2A\n'
              'mIL7WG2Kuf0tYorKxYrmDsYv9dChRANCAATflHfL1gYZ5UpfuMM+PYWEFW24EwLH\n'
              'nrcihKZkm1+CEhPS04Oo88W2w3eKaguvx4D5whk0jWM8AbwYnXOCsbo7\n'
              '-----END EC PRIVATE KEY-----')
CA_NAME = '/coal-exam/CA/example-ca'
CA_KEY_NAME = CA_NAME + '/KEY/ABCDEFGH'
ROLE_PREFIXES = [Name.from_str('/coal-exam/ROLE/role1'),
                 Name.from_str('/coal-exam/ROLE/role2')]


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')

app = NDNApp()

# Prepare trust anchor for demonstration
ca_prv_key = ECC.import_key(CA_PRV_KEY)
ca_prv_key_bits = ca_prv_key.export_key(format='DER', use_pkcs8=False)
ca_pub_key_bits = ca_prv_key.public_key().export_key(format='DER')
_, cert = ndnsec.self_sign(CA_KEY_NAME, ca_pub_key_bits,
                           Sha256WithEcdsaSigner(CA_KEY_NAME, ca_prv_key_bits))


@app.route(CA_NAME + '/KEY')
def on_cert_int(_name, _param, _app_param):
    app.put_raw_packet(cert)


async def after_start():
    ca = CaServer(app, Name.from_str(CA_NAME), Name.from_str(CA_KEY_NAME), ca_prv_key_bits, ROLE_PREFIXES)
    await ca.register()
    await aio.sleep(0.1)
    print('CA is ready')


if __name__ == '__main__':
    app.run_forever(after_start=after_start())
