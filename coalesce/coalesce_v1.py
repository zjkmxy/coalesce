# This file implements a proof-of-concept protocol with RBAC
import time
import typing
import logging
import secrets
from dataclasses import dataclass
from hashlib import sha256
import asyncio as aio
from datetime import datetime, timedelta
from Cryptodome.PublicKey import ECC
from ndn.app import NDNApp
import ndn.encoding as enc
import ndn.security as sec
from . import butterfly as bf
from .utils import derive_cert, ecc_checker


# ===== Encoding =====

class MasterKeyModel(enc.TlvModel):
    name = enc.NameField()
    is_private = enc.BoolField(0x91)
    base_key = enc.BytesField(0x92)
    seed = enc.BytesField(0x93)
    start_time = enc.UintField(0x95)

    @staticmethod
    def create(name, master_key: bf.MasterKey, start_time: typing.Optional[int]):
        ret = MasterKeyModel()
        ret.name = enc.Name.normalize(name)
        if master_key.base_key.has_private():
            ret.is_private = True
            ret.base_key = master_key.base_key.export_key(format='DER', use_pkcs8=False)
        else:
            ret.is_private = False
            ret.base_key = master_key.base_key.export_key(format='DER')
        ret.seed = master_key.seed
        ret.start_time = start_time
        return ret

    def master_key(self) -> bf.MasterKey:
        seed = bytes(self.seed) if self.seed is not None else None
        return bf.MasterKey(base_key=ECC.import_key(bytes(self.base_key)),
                            seed=seed)


class BfRequest(enc.TlvModel):
    encrypted_master = enc.BytesField(0xa1)
    encrypt_key_name = enc.BytesField(0xa2)


class RoleModel(enc.TlvModel):
    role_name = enc.NameField()
    renew_interval = enc.UintField(0xb1)


class BfResponse(enc.TlvModel):
    status_code = enc.UintField(0xc1)
    seed_encrypted = enc.BytesField(0xc2)
    approved_roles = enc.RepeatedField(enc.ModelField(0xc3, RoleModel))
    start_time = enc.UintField(0xc4)


# ===== Key Name Related =====

def gen_master_name(id_name, _key: bf.MasterKey):
    key_id = f'KEY/coalesce-{secrets.token_hex(4)}'
    return id_name + enc.Name.from_str(key_id)


def derive_key_name(master_name, role_name, i):
    master_id = enc.Component.to_str(master_name[-1])
    device_id = master_name[-3]
    key_id = f'KEY/{master_id}-{i}'
    return role_name + [device_id] + enc.Name.from_str(key_id)


# ===== Application =====

@dataclass
class Role:
    role_name: enc.FormalName
    key_name: enc.FormalName = None
    private_key: ECC.EccKey = None
    renew_interval: int = None
    tick_cnt: int = None


class Requester:
    app: NDNApp
    name: enc.FormalName
    master_key_name: enc.FormalName
    master_key: bf.MasterKey
    ca_name: enc.FormalName
    ca_public_key: ECC.EccKey
    start_time: typing.Optional[int]
    roles: typing.List[Role]

    master_data: bytes

    def __init__(self, app, name, ca_name, ca_public_key, role_names):
        self.app = app
        self.name = name
        self.ca_name = ca_name
        self.ca_public_key = ECC.import_key(ca_public_key)
        self.start_time = None
        self.roles = []
        for name in role_names:
            # This is a quick and dirty hack
            # In real world, the application should learn these from security schema
            # Renew Interval should agree with CA
            self.roles.append(Role(role_name=name, tick_cnt=-1,
                                   renew_interval=10))

    def load_master_key(self, blob: bytes):
        model = MasterKeyModel.parse(blob)
        self.master_key = model.master_key()
        self.master_key_name = model.name
        self.start_time = model.start_time

    def save_master_key(self) -> bytes:
        model = MasterKeyModel.create(self.master_key_name, self.master_key, self.start_time)
        return model.encode()

    def gen_master_key(self):
        self.master_key = bf.MasterKey.generate()
        self.master_key_name = gen_master_name(self.name, self.master_key)

    def generate_master_data(self):
        pub_key = self.master_key.to_public()
        model = MasterKeyModel.create(self.master_key_name, pub_key, None)
        sign_key_der = self.master_key.base_key.export_key(format='DER', use_pkcs8=False)
        # Do we need to encrypt this with CA's KEY?
        self.master_data = bytes(self.app.prepare_data(
            name=self.master_key_name,
            content=model.encode(),
            freshness_period=3600000,
            signer=sec.Sha256WithEcdsaSigner(
                key_name=self.master_key_name,
                key_der=sign_key_der)))

    def register(self):
        self.generate_master_data()

        @self.app.route(self.name + enc.Name.normalize('/KEY'))
        def on_key_int(name, _param, _app_param):
            if name == self.master_key_name:
                self.app.put_raw_packet(self.master_data)
            else:
                logging.warning(f'Key not found: {enc.Name.to_str(name)}')
                logging.info(f'Existing keys: {enc.Name.to_str(self.master_key_name)}')

    def renew(self):
        if self.master_key.seed is None or not self.start_time:
            logging.error(f'Cannot derive keys before bootstrapping with CA')
            return
        time_delta = int(time.time()) - self.start_time
        for role in self.roles:
            i = time_delta // role.renew_interval
            if i == role.tick_cnt:
                continue
            role.tick_cnt = i
            role.key_name = derive_key_name(self.master_key_name, role.role_name, i)
            role.private_key = self.master_key.derive_private_key(enc.Name.encode(role.key_name), i)
            logging.info(f'Renewed key {enc.Name.to_str(role.key_name)}')

    async def auto_renew(self, on_renew: typing.Callable):
        wait_time = min(role.renew_interval for role in self.roles)
        while True:
            self.renew()
            on_renew()
            await aio.sleep(wait_time)

    def signer(self, i):
        sign_key_der = self.roles[i].private_key.export_key(format='DER', use_pkcs8=False)
        return sec.Sha256WithEcdsaSigner(key_name=self.roles[i].key_name,
                                         key_der=sign_key_der)

    async def bootstrap(self):
        app_param = enc.Name.encode(self.master_key_name)
        sign_key_der = self.master_key.base_key.export_key(format='DER', use_pkcs8=False)

        # TODO: Error handling
        _, _, content = await self.app.express_interest(
            name=self.ca_name + enc.Name.from_str('/boot'),
            app_param=app_param,
            must_be_fresh=True,
            can_be_prefix=False,
            lifetime=4000,
            signer=sec.Sha256WithEcdsaSigner(
                key_name=self.master_key_name,
                key_der=sign_key_der),
            validator=ecc_checker(self.ca_public_key))

        res = BfResponse.parse(content)
        self.start_time = res.start_time
        st_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(res.start_time))
        logging.info(f'Bootstrap response: code={res.status_code} time={st_time}')
        self.master_key.decrypt_seed(bytes(res.seed_encrypted))
        for i, _ in enumerate(self.roles):
            role = Role(role_name=self.roles[i].role_name)
            role.renew_interval = None
            role.tick_cnt = -1
            for r in res.approved_roles:
                if role.role_name != r.role_name:
                    continue
                role.renew_interval = r.renew_interval
                break
            if not role.renew_interval:
                logging.error(f'Role {enc.Name.to_str(role.role_name)} is not approved.')
            else:
                logging.info(f'Role {enc.Name.to_str(role.role_name)} approved with renew time {role.renew_interval}s')
            self.roles[i] = role


class CaServer:
    app: NDNApp
    name: enc.FormalName
    role_set: typing.List[RoleModel]
    cert_db: typing.Dict[bytes, bytes]
    ca_prv_key: bytes
    ca_key_name: enc.FormalName

    def __init__(self, app, name, ca_key_name, ca_prv_key, role_names):
        self.app = app
        self.name = enc.Name.normalize(name)
        self.role_set = []
        self.cert_db = {}
        self.ca_key_name = enc.Name.normalize(ca_key_name)
        self.ca_prv_key = ca_prv_key
        for name in role_names:
            model = RoleModel()
            model.role_name = name
            model.renew_interval = 10
            self.role_set.append(model)

    async def register(self):
        @self.app.route(self.name + enc.Name.normalize('/boot'))
        def on_boot_int(name, _param, app_param):
            master_key_name = enc.Name.from_bytes(app_param)
            logging.info(f'Bootstrap request: {enc.Name.to_str(master_key_name)}')
            aio.create_task(self.bootstrap(name, master_key_name))
            # This is a PoC implementation
            # In real world, CA should return immediately like a RPC

        for role in self.role_set:
            l = len(role.role_name)

            def on_cert_int(name, _param, _app_param):
                if name[l+1] != enc.Component.from_str('KEY'):
                    return
                key_name = name[:l+3]
                key_index = sha256(enc.Name.encode(key_name)).digest()
                cert = self.cert_db.get(key_index)
                if not cert:
                    return
                self.app.put_raw_packet(cert)

            await self.app.register(role.role_name, on_cert_int)

    async def bootstrap(self, int_name, master_key_name):
        _, _, content = await self.app.express_interest(
            name=master_key_name,
            must_be_fresh=True,
            can_be_prefix=False,
            lifetime=4000)
        model = MasterKeyModel.parse(content)
        master_key = model.master_key()
        master_key.pick_seed()
        res = BfResponse()
        res.approved_roles = []
        signer = sec.Sha256WithEcdsaSigner(key_name=self.ca_key_name, key_der=self.ca_prv_key)
        for role in self.role_set:
            # For demo, just issue 10 certificates, granting privilege for 100 seconds
            for i in range(10):
                key_name = derive_key_name(model.name, role.role_name, i)
                pub_key = master_key.derive_public_key(enc.Name.encode(key_name), i)
                pub_key_bits = pub_key.export_key(format='DER')

                start_time = datetime.utcnow()
                delta_time = timedelta(seconds=10*i)
                start_time += delta_time

                cert_name, cert = derive_cert(key_name, b'Coalesce', pub_key_bits,
                                              signer, start_time=start_time, expire_sec=40)
                # Quick and dirty hack, should use the certificate name and match in real world
                self.cert_db[sha256(bytes(enc.Name.encode(key_name))).digest()] = cert
                logging.info(f'Issued certificate: {enc.Name.to_str(cert_name)}')
            res.approved_roles.append(role)
        res.status_code = 1
        res.start_time = int(time.time())
        res.seed_encrypted = master_key.encrypt_seed()
        res_bytes = res.encode()
        self.app.put_data(int_name, res_bytes, signer=signer, freshness_period=10000)

