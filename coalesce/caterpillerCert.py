import ECIES
from Cryptodome.PublicKey import ECC
from cocoon import CocoonsKey
import butterfly


class CaterpillarCert:
    key_id: bytes
    pub_key: ECC.EccKey

    def deriveCooconKeys(self, C: bytes, i: int) -> CocoonsKey:
        # Algorithm 4: Derive Butterfly Private Keys from encrypted C
        if i < 0 or i >= (1 << 64):
            raise ValueError(f'Input {i=} should be a 64-bit integer')
        #qi = (self.p + f_2(self.ek, i)) % SECP256R1_N
        c_bytes = ECIES.decrypt(ECC.EccKey(d=self.p, curve=ECC_CURVE), C)
        c = int(ECC.import_key(c_bytes).d)
        bi = (self.a + butterfly.f_1(self.ck, i)) % SECP256R1_N
        bf_prv_key = (bi + c) % SECP256R1_N
        return CocoonsKey(key_id=f_name(self.key_id, i),
                            prv_key=ECC.EccKey(d=bf_prv_key, curve=ECC_CURVE))
