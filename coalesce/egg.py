from caterpiller import Caterpillar
from dataclasses import dataclass
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import ECC
import ndn.encoding as enc
import butterfly


class Egg:
    "classes for egg keys"
    
    
    def layingEggkeys(self, i: int) -> Caterpillar:
        # Algorithm 2: Generate Cocoon Keys from public Caterpillar
        if i < 0 or i >= (1 << 64):
            raise ValueError(f'Input {i=} should be a 64-bit integer')
        return Caterpillar(key_id=f_name(self.key_id, i),
                      Bi=self.A + GEN_P256 * butterfly.f_1(self.ck, i))
