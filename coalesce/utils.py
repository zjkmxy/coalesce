from datetime import timedelta
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from ndn.encoding import Name, MetaInfo, Component, ContentType, \
    get_tl_num_size, write_tl_num, TypeNumber, SignaturePtrs, FormalName
from ndn.app_support.security_v2 import CertificateV2Value, CertificateV2SignatureInfo, ValidityPeriod
from ndn.utils import timestamp
from ndn.app import Validator


def derive_cert(key_name, issuer_id, pub_key, signer, start_time, expire_sec):
    cert_val = CertificateV2Value()
    cert_name = Name.normalize(key_name) + [Component.from_bytes(issuer_id), Component.from_version(timestamp())]
    cert_val.name = cert_name
    cert_val.content = pub_key
    cert_val.meta_info = MetaInfo(content_type=ContentType.KEY, freshness_period=3600000)
    cert_val.signature_info = CertificateV2SignatureInfo()
    cert_val.signature_info.validity_period = ValidityPeriod()
    cur_time = start_time
    not_before = (f'{cur_time.year:04}{cur_time.month:02}{cur_time.day:02}T'
                  f'{cur_time.hour:02}{cur_time.minute:02}{cur_time.second:02}').encode()
    cert_val.signature_info.validity_period.not_before = not_before
    delta = timedelta(seconds=expire_sec)
    end_time = cur_time + delta
    not_after = (f'{end_time.year:04}{end_time.month:02}{end_time.day:02}T'
                 f'{end_time.hour:02}{end_time.minute:02}{end_time.second:02}').encode()
    cert_val.signature_info.validity_period.not_after = not_after

    markers = {}
    cert_val._signer.set_arg(markers, signer)
    value = cert_val.encode(markers=markers)
    shrink_size = cert_val._shrink_len.get_arg(markers)
    type_len = get_tl_num_size(TypeNumber.DATA)
    size_len = get_tl_num_size(len(value) - shrink_size)
    buf = bytearray(type_len + size_len + len(value) - shrink_size)
    write_tl_num(TypeNumber.DATA, buf)
    write_tl_num(len(value) - shrink_size, buf, type_len)
    buf[type_len+size_len:] = memoryview(value)[0:len(value)-shrink_size]
    return cert_name, buf


def ecc_checker(pub_key: ECC.EccKey) -> Validator:
    async def validator(_name: FormalName, sig_ptrs: SignaturePtrs) -> bool:
        # if not sig_ptrs.signature_info or sig_ptrs.signature_info.name != key_name:
        #     return False
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
