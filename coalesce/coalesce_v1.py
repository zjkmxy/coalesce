import typing
import logging
from hashlib import sha256
import asyncio as aio
from Cryptodome.PublicKey import ECC
from ndn.app import NDNApp
import ndn.encoding as enc
import ndn.security as sec
import ndn.app_support.security_v2 as ndnsec
from . import butterfly as bf
from . import ECIES
from .utils import derive_cert


# class CaterpillarData(enc.TlvModel):
#     ax = enc.UintField(0x81)
#     ay = enc.UintField(0x82)
#     hx = enc.UintField(0x83)
#     hy = enc.UintField(0x84)
#     ck = enc.BytesField(0x85)
#     ek = enc.BytesField(0x86)


class BfRequest(enc.TlvModel):
    cater_key_name = enc.NameField(0x91)
    i = enc.UintField(0x92)
    j = enc.UintField(0x93)


class BfResponse(enc.TlvModel):
    cert = enc.BytesField(0xa1)
    c_prv = enc.BytesField(0xa2)


class Requester:
    app: NDNApp
    cater: bf.Caterpillar
    cater_id: bytes
    cater_data: bytes
    name: enc.FormalName
    ca_name: enc.FormalName
    bf_id: bytes
    bf_signer: enc.Signer
    bf_cert: bytes

    def __init__(self, app, caterpillar, name, ca_name):
        self.app = app
        self.cater = caterpillar
        self.name = enc.Name.normalize(name)
        self.ca_name = enc.Name.normalize(ca_name)
        self.cater_id = enc.Component.from_str('caterpillar-' + sha256(caterpillar.save_prv()).hexdigest()[:16])

    def generate_cater_data(self):
        pub_key = self.cater.public_key()
        cater_key_name = self.name + [enc.Component.from_str('KEY'), self.cater_id]
        self.cater_data = self.app.prepare_data(
            name=cater_key_name,
            content=pub_key.export_pub(),
            freshness_period=3600000,
            signer=sec.Sha256WithEcdsaSigner(
                key_name=cater_key_name,
                key_der=self.cater.sign_key()))

    def register(self):
        self.generate_cater_data()

        @self.app.route(self.name + enc.Name.normalize('/KEY'))
        def on_key_int(name, _param, _app_param):
            key_id = name[len(self.name)+1]
            if key_id == self.cater_id:
                self.app.put_raw_packet(self.cater_data)
            elif key_id == self.bf_id:
                self.app.put_raw_packet(self.bf_cert)
            else:
                logging.warning(f'Key not found: {enc.Name.to_str(name)}')
                logging.info(f'Existing keys: {enc.Component.to_str(self.cater_id)}'
                             f' {enc.Component.to_str(self.bf_id)}')

    async def renew(self):
        cocoon = self.cater.derive_cocoon()
        cater_key_name = self.name + [enc.Component.from_str('KEY'), self.cater_id]
        req = BfRequest()
        req.cater_key_name = cater_key_name
        req.i = cocoon.i
        req.j = cocoon.j
        app_param = req.encode()

        # TODO: Error handling
        data_name, _, content = await self.app.express_interest(
            name=self.ca_name + enc.Name.from_str('/renew'),
            app_param=app_param,
            must_be_fresh=True,
            can_be_prefix=False,
            lifetime=4000,
            signer=sec.Sha256WithEcdsaSigner(
                key_name=cater_key_name,
                key_der=self.cater.sign_key()))

        plain_res = ECIES.decrypt(cocoon.decrypt_key(), bytes(content))
        res = BfResponse.parse(plain_res)
        prv_der = bytes(res.c_prv)
        bf_prv = cocoon.butterfly_prv(ECC.import_key(prv_der))
        cert_val = ndnsec.parse_certificate(res.cert)

        self.bf_id = cert_val.name[len(self.name)+1]
        self.bf_cert = res.cert
        self.bf_signer = sec.Sha256WithEcdsaSigner(
                key_name=cert_val.name,
                key_der=bf_prv.export_key(format='DER', use_pkcs8=False))

    def signer(self):
        return self.bf_signer

    async def bootstrap(self):
        cater_key_name = self.name + [enc.Component.from_str('KEY'), self.cater_id]
        app_param = enc.Name.encode(cater_key_name)

        # TODO: Error handling
        _, _, _ = await self.app.express_interest(
            name=self.ca_name + enc.Name.from_str('/boot'),
            app_param=app_param,
            must_be_fresh=True,
            can_be_prefix=False,
            lifetime=4000,
            signer=sec.Sha256WithEcdsaSigner(
                key_name=cater_key_name,
                key_der=self.cater.sign_key()))


class CaServer:
    app: NDNApp
    cater_db: typing.Dict[bytes, bf.Caterpillar]
    name: enc.FormalName

    def __init__(self, app, name):
        self.app = app
        self.name = enc.Name.normalize(name)
        self.cater_db = {}

    def register(self):
        @self.app.route(self.name + enc.Name.normalize('/boot'))
        def on_boot_int(name, _param, app_param):
            cater_name = enc.Name.from_bytes(app_param)
            logging.info(f'Bootstrap request: {enc.Name.to_str(cater_name)}')
            aio.create_task(self.fetch_cater(cater_name))
            self.app.put_data(name, 'OK'.encode(), freshness_period=10000)

        @self.app.route(self.name + enc.Name.normalize('/renew'))
        def on_renew_int(name, _param, app_param):
            req = BfRequest.parse(app_param)
            cater_name = req.cater_key_name
            i = req.i
            j = req.j

            cater_id = sha256(enc.Name.to_bytes(cater_name)).digest()
            cater = self.cater_db.get(cater_id)
            if cater is None:
                logging.warning(f'Renew request: {enc.Name.to_str(cater_name)} - not exist')
                return

            logging.warning(f'Renew request: {enc.Name.to_str(cater_name)} - processing')
            self.respond_butterfly(name, cater_name, cater.derive_cocoon(i, j))
            logging.warning(f'Renew request: {enc.Name.to_str(cater_name)} - responded')

    async def fetch_cater(self, cater_name):
        _, _, content = await self.app.express_interest(
            name=cater_name,
            must_be_fresh=True,
            can_be_prefix=False,
            lifetime=4000)

        cater_pub = bf.Caterpillar.import_pub(bytes(content))
        cater_id = sha256(enc.Name.to_bytes(cater_name)).digest()
        self.cater_db[cater_id] = cater_pub

    def respond_butterfly(self, name, cater_name, cocoon):
        c_prv, bf_pub = cocoon.hatch()
        bf_id = enc.Component.from_str(f'butterfly-{cocoon.i}-{cocoon.j}')
        key_name = cater_name[:-1] + [bf_id]
        pub_key = bytes(bf_pub.export_key(format='DER'))

        _, cert = derive_cert(key_name, b'Coalesce', pub_key, self.app.keychain.get_signer({}), expire_sec=4)
        prv_der = c_prv.export_key(format='DER', use_pkcs8=False)
        res = BfResponse()
        res.cert = cert
        res.c_prv = prv_der
        res_wire = bytes(res.encode())
        encrypt_res = ECIES.encrypt(cocoon.encrypt_key(), res_wire)

        self.app.put_data(name, encrypt_res, freshness_period=10000)
