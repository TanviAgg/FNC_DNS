from enum import Enum


class DNSRecordType(Enum):
    A = "A"
    NS = "NS"
    MX = "MX"
    DNSKEY = "DNSKEY"


# ROOT server IPs downloaded from https://www.iana.org/domains/root/servers
ROOT_SERVER_IPS = ["199.7.91.13", "192.203.230.10", "198.41.0.4", "199.9.14.201", "192.33.4.12",
                   "192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
                   "193.0.14.129", "199.7.83.42", "202.12.27.33"]


# Root trust anchor from http://data.iana.org/root-anchors/root-anchors.xml (updated 2018-12-20)
ROOT_ANCHORS = ["19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5",
                "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"]


def get_record_type(record_type: str) -> DNSRecordType:
    if record_type == 'A':
        return DNSRecordType.A
    elif record_type == 'NS':
        return DNSRecordType.NS
    elif record_type == 'MX':
        return DNSRecordType.MX
    else:
        return None