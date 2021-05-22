from datetime import datetime, timedelta
from ndn.encoding import Name, MetaInfo, Component, ContentType, get_tl_num_size, write_tl_num, TypeNumber
from ndn.app_support.security_v2 import CertificateV2Value, CertificateV2SignatureInfo, ValidityPeriod
from ndn.utils import timestamp


def derive_cert(key_name, issuer_id, pub_key, signer, expire_sec):
    cert_val = CertificateV2Value()
    cert_name = Name.normalize(key_name) + [Component.from_bytes(issuer_id), Component.from_version(timestamp())]
    cert_val.name = cert_name
    cert_val.content = pub_key
    cert_val.meta_info = MetaInfo(content_type=ContentType.KEY, freshness_period=3600000)
    cert_val.signature_info = CertificateV2SignatureInfo()
    cert_val.signature_info.validity_period = ValidityPeriod()
    cur_time = datetime.utcnow()
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
