from dataclasses import dataclass
from Cryptodome.PublicKey import ECC


@dataclass
class CocoonKey:
    key_id: bytes
    prv_key: ECC.EccKey
