from enum import Enum
from dataclasses import dataclass


@dataclass
class DNSResponse:
    ip: str
    timestamp: str
    query_time: int
    raw_response: str


class Error(Enum):
    NOT_SUPPORTED = "DNSSEC not supported"
    VERIFICATION_FAILED = "DNSSec verification failed"


class DNSRecordType(Enum):
    A = "A"
    NS = "NS"
    MX = "MX"


ROOT_SERVER_IPS = ["199.7.91.13", "192.203.230.10", "198.41.0.4", "199.9.14.201", "192.33.4.12",
                   "192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
                   "193.0.14.129", "199.7.83.42", "202.12.27.33"]
