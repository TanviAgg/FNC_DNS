import sys
from datetime import datetime

from data import DNSRecordType, ROOT_SERVER_IPS, ROOT_ANCHORS, get_record_type
import dns.message
import dns.query
from dns.rdatatype import RdataType as RecordType
import time


QUESTION_SECTION = 0
ANSWER_SECTION = 1
AUTHORITY_SECTION = 2
ADDITIONAL_SECTION = 3


def print_dns_response(response: dns.message, query_time: int):
    print("QUESTION SECTION:")
    print(response.sections[QUESTION_SECTION][0].to_text())
    print()
    if len(response.sections[ANSWER_SECTION]) > 0:
        print("ANSWER SECTION:")
        for record in response.sections[ANSWER_SECTION]:
            print(record.to_text())
        print()
    if len(response.sections[AUTHORITY_SECTION]) > 0:
        print("AUTHORITY SECTION:")
        for record in response.sections[AUTHORITY_SECTION]:
            print(record.to_text())
        print()
    print("QUERY TIME: {} msec".format(query_time))
    print("WHEN: ", datetime.today())
    print("MSG SIZE rcvd: ", sys.getsizeof(response.to_text()))


def match_type(type1: RecordType, type2: DNSRecordType) -> bool:
    if type1 == RecordType.A and type2 == DNSRecordType.A:
        return True
    if type1 == RecordType.NS and type2 == DNSRecordType.NS:
        return True
    if type1 == RecordType.MX and type2 == DNSRecordType.MX:
        return True
    return False


def getPubKSK(record):
    """ extract the public key signing key from record set """
    for r in record:
        if r.flags == 257:
            return r
    return None


# def getPubZSK(record):
#     """ extract the public zone signing key from record set """
#     return ""


def getDNSKeyRecord(response):
    """ return the DNSKey record from answer """
    # check answer section for DNSKey
    if len(response.sections[ANSWER_SECTION]) > 0:
        for record in response.sections[ANSWER_SECTION]:
            if record.rdtype == dns.rdatatype.DNSKEY:
                return record
    return None


def getRRSig(response, authority=False):
    """ extract the RRSig from the response """
    # check answer section for DNSKey RRSig
    if not authority:
        if len(response.sections[ANSWER_SECTION]) > 0:
            for record in response.sections[ANSWER_SECTION]:
                if record.rdtype == dns.rdatatype.RRSIG:
                    return record
    # check authority section for DS RRSig
    else:
        if len(response.sections[AUTHORITY_SECTION]) > 0:
            for record in response.sections[AUTHORITY_SECTION]:
                if record.rdtype == dns.rdatatype.RRSIG:
                    return record
    return None


def getRRSet(response, record_type):
    # check answer section for A record
    if record_type == dns.rdatatype.A:
        if len(response.sections[ANSWER_SECTION]) > 0:
            for record in response.sections[ANSWER_SECTION]:
                if record.rdtype == dns.rdatatype.A:
                    return record
    # check authority section for DS record
    if record_type == dns.rdatatype.DS:
        if len(response.sections[AUTHORITY_SECTION]) > 0:
            for record in response.sections[AUTHORITY_SECTION]:
                if record.rdtype == dns.rdatatype.DS or record.rdtype == dns.rdatatype.NSEC:
                    return record

    return None


def verify_signature(rrset, rrsig, dnskey):
    """ verify that the RRSet's RRSig was signed by the private key corresponding to given public key """
    try:
        # n = dnskey.name
        dns.dnssec.validate(rrset=rrset, rrsigset=rrsig, keys={dnskey.name: dnskey})
        return True
    except dns.dnssec.ValidationFailure as e:
        return False


def verify_fingerprint(pubkey, ds_record):
    """ verify that the hash of the given public key matches the DS record from parent """
    try:
        domain = "."
        parent_record_text = ROOT_ANCHORS[1].lower()
        hash_alg = 'SHA256'
        if ds_record is not None:
            domain = ds_record.name.to_text()
            parent_record_text = ds_record[0].to_text()
            if ds_record[0].digest_type == 1:
                hash_alg = 'SHA1'
        hash_value = dns.dnssec.make_ds(name=domain, key=pubkey, algorithm=hash_alg)
        if hash_value.to_text() == parent_record_text:
            return True
        else:
            return False
    except dns.dnssec.ValidationFailure as e:
        return False


def hasARecord(response):
    if len(response.sections[ANSWER_SECTION]) > 0:
        for record in response.sections[ANSWER_SECTION]:
            if record.rdtype == dns.rdatatype.A:
                return True
    return False


def verify_record_and_zone(dns_key_response, dns_response, parent_record=None):
    """ verification of DNSKEY and response """
    dnsKeyRecord = getDNSKeyRecord(dns_key_response)
    if dnsKeyRecord is None:
        print("DNSSec not supported since we could not find DNSKey record for zone '{}'".
              format('.' if parent_record is None else parent_record.name.to_text()))
        return False, None
    pubKSK = getPubKSK(dnsKeyRecord)

    # verify RRSig of DNSKey record
    dnskey_rrsig = getRRSig(dns_key_response)
    rrsig_verified = verify_signature(dnsKeyRecord, dnskey_rrsig, dnsKeyRecord)
    if not rrsig_verified:
        print("RRSig verification failed for DNSKey record for zone '{}'".format(dnsKeyRecord.name.to_text()))
        return False, None
    print("RRSig verification passed for DNSKey record for zone '{}'".format(dnsKeyRecord.name.to_text()))

    # verify RRSig of A/DS record
    if hasARecord(dns_response):
        a_rrsig = getRRSig(dns_response)
        parent_rrset = getRRSet(dns_response, dns.rdatatype.A)
        if parent_rrset is None:
            print("DNSSec not supported since we could not find A record from parent zone '{}'".format(
                dnsKeyRecord.name.to_text()))
            return False, None
        rrsig_verified = verify_signature(parent_rrset, a_rrsig, dnsKeyRecord)
        if not rrsig_verified:
            print("RRSig verification failed for A record from parent zone '{}'".format(dnsKeyRecord.name.to_text()))
            return False, None
        print("RRSig verification passed for A record from parent zone '{}'".format(dnsKeyRecord.name.to_text()))
    else:
        ds_rrsig = getRRSig(dns_response, authority=True)
        parent_rrset = getRRSet(dns_response, dns.rdatatype.DS)
        if parent_rrset is None:
            print("DNSSec not supported since we could not find DS record from parent zone '{}'".format(
                dnsKeyRecord.name.to_text()))
            return False, None
        rrsig_verified = verify_signature(parent_rrset, ds_rrsig, dnsKeyRecord)
        if not rrsig_verified:
            print("RRSig verification failed for DS record from parent zone '{}'".format(dnsKeyRecord.name.to_text()))
            return False, None
        print("RRSig verification passed for DS record from parent zone '{}'".format(dnsKeyRecord.name.to_text()))

    # verify zone by checking hash of PubKSK and DS record from parent
    zone_verified = verify_fingerprint(pubKSK, parent_record)
    if not zone_verified:
        print("Zone verification failed for zone '{}'".format(dnsKeyRecord.name.to_text()))
        return False, None
    print("Zone verification passed for zone '{}'".format(dnsKeyRecord.name.to_text()))
    print()
    return True, parent_rrset


class DNSSecResolver:
    def __init__(self, use_tcp=False):
        self.root_server_ips = ROOT_SERVER_IPS
        self.use_tcp = use_tcp
        self.timeout = 5

    def resolve(self, domain: str, record_type: DNSRecordType) -> dns.message:
        return self._resolve(domain, record_type, 0)

    def _resolve(self, domain: str, record_type: DNSRecordType, level: int, nameserver: bool = False) -> dns.message:
        # print("resolve domain:", domain)
        resolution = None
        # query root servers for record
        for root_server in self.root_server_ips:
            root_dns_key_resp = self._query(query_domain=".", nameserver=root_server, record_type=DNSRecordType.DNSKEY)
            resolution = self._query(query_domain=domain, nameserver=root_server, record_type=record_type)
            # if this query failed, try other root servers
            if root_dns_key_resp is None or resolution is None:
                continue

            # DNSSec validation
            verified, parent_record = verify_record_and_zone(dns_key_response=root_dns_key_resp, dns_response=resolution)
            if not verified:
                print("DNSSec verification failed for root server with ip {}".format(root_server))
                return None

            # check if answer is present
            while len(resolution.sections[ANSWER_SECTION]) == 0:
                # ============= ADDITIONAL SECTION ==============
                # check additional section
                # process all A type records (ignore AAAA)
                if len(resolution.sections[ADDITIONAL_SECTION]) > 0:
                    for record in resolution.sections[ADDITIONAL_SECTION]:
                        if record[0].rdtype != RecordType.A:
                            continue
                        # try to resolve the given domain using address in record with required type
                        nameserver_address = record[0].address
                        dns_key_resp = self._query(query_domain=parent_record.name.to_text(),
                                                   nameserver=nameserver_address,
                                                   record_type=DNSRecordType.DNSKEY)
                        resp = self._query(query_domain=domain, nameserver=nameserver_address, record_type=record_type)
                        # if this query failed, try other records
                        if dns_key_resp is None or resp is None:
                            continue
                        # DNSSec validation
                        validated, parent_record = verify_record_and_zone(dns_key_response=dns_key_resp,
                                                                          dns_response=resp,
                                                                          parent_record=parent_record)
                        if not validated:
                            print("DNSSec verification failed for nameserver with ip {}".format(nameserver_address))
                            return None

                        # otherwise check answer
                        if len(resp.sections[ANSWER_SECTION]) > 0:
                            if nameserver and resp.sections[ANSWER_SECTION][0].rdtype == RecordType.CNAME:
                                return resp
                            elif resp.sections[ANSWER_SECTION][0].rdtype == RecordType.A:
                                return resp
                        resolution = resp
                        break
                # ============= AUTHORITY SECTION ==============
                # check authority section
                # if any nameservers are returned, try to resolve them or else return SOA
                elif len(resolution.sections[AUTHORITY_SECTION]) > 0:
                    for record in resolution.sections[AUTHORITY_SECTION]:
                        # if no additional records are present and we have only SOA,
                        # further resolution is not possible, so return
                        if record[0].rdtype == RecordType.SOA:
                            return resolution
                        # try to resolve the address for authoritative name server starting from root server
                        nameserver_name = record[0].target.to_text()
                        print("Resolving address for {} starting from root".format(nameserver_name))
                        resp = self._resolve(nameserver_name, DNSRecordType.A, 0)
                        # if this query failed, try other records
                        if resp is None:
                            continue
                        # if we wanted nameserver resolution, return
                        # else we query the nameserver for given domain
                        if nameserver:
                            return resp
                        elif len(resp.sections[ANSWER_SECTION]) > 0:
                            for auth_record in resp.sections[ANSWER_SECTION]:
                                # query the IP address of nameserver for this domain
                                dns_key_resp = self._query(query_domain=parent_record.name.to_text(),
                                                           nameserver=auth_record[0].address,
                                                           record_type=DNSRecordType.DNSKEY)
                                auth_resp = self._query(query_domain=domain, record_type=record_type,
                                                        nameserver=auth_record[0].address)
                                if dns_key_resp is None or auth_resp is None:
                                    continue

                                # DNSSec validation
                                validated, parent_record = verify_record_and_zone(dns_key_response=dns_key_resp,
                                                                                  dns_response=auth_resp,
                                                                                  parent_record=parent_record)
                                if not validated:
                                    print("DNSSec verification failed for auth nameserver with ip {}".format(
                                        auth_record[0].address))
                                    return None
                                resolution = auth_resp
                                break
            # ============= ANSWER SECTION ==============
            # check answer section
            # 1. if answer section contains desired record type, return resolution answer
            # 2. if it contains SOA type record, return answer
            if len(resolution.sections[ANSWER_SECTION]) > 0:
                for record in resolution.sections[ANSWER_SECTION]:
                    if match_type(record.rdtype, record_type):
                        return resolution
                    elif record.rdtype == RecordType.SOA:
                        return resolution
                # check if CNAME records are present and handle
                # we need to resolve CNAME further until we get SOA/A records
                for record in resolution.sections[ANSWER_SECTION]:
                    while record.rdtype == RecordType.CNAME:
                        cname_address = record[0].target.to_text()
                        resp = self._resolve(domain=cname_address, record_type=record_type, level=0, nameserver=True)
                        # if this query failed, try other records
                        if resp is None:
                            continue
                        # check answer section
                        if len(resp.sections[ANSWER_SECTION]) == 0:
                            # check authority section if present
                            # sometimes we only get SOA records
                            for c_record in resp.sections[AUTHORITY_SECTION]:
                                if c_record.rdtype == RecordType.SOA:
                                    resolution.sections[AUTHORITY_SECTION] = resp.sections[AUTHORITY_SECTION]
                                    # break
                                    print("return here")
                                    return resolution
                        for c_record in resp.sections[ANSWER_SECTION]:
                            # if we got CNAME again, add to the answer to process further
                            if c_record.rdtype == RecordType.CNAME:
                                resolution.sections[ANSWER_SECTION].append(c_record)
                                break
                            # if we got A record of cname, add to answer
                            elif c_record.name.to_text() == cname_address and \
                                    (c_record.rdtype == RecordType.A and record_type == DNSRecordType.A):
                                resolution.sections[ANSWER_SECTION].append(c_record)
                                resolution.sections[AUTHORITY_SECTION] = []
                                # break
                                print("return here 4")
                                return resolution
                            # otherwise query server in this record to find CNAME
                            else:
                                nameserver_address = c_record[0].address
                                ns_resp = self._query(query_domain=cname_address,
                                                      nameserver=nameserver_address,
                                                      record_type=record_type)
                                if ns_resp is None:
                                    continue
                                # if we found answer, add it to the main response
                                if len(ns_resp.sections[ANSWER_SECTION]) > 0:
                                    resolution.sections[ANSWER_SECTION].extend(ns_resp.sections[ANSWER_SECTION])
                                    resolution.sections[AUTHORITY_SECTION] = []
                                    # print("return here 3")
                                    # return resolution   # cannot return because it breaks www.netflix.com A
                                # otherwise check authority section
                                elif len(ns_resp.sections[AUTHORITY_SECTION]) > 0:
                                    # if we are not looking for A record, add records to main response
                                    if record_type == DNSRecordType.NS or record_type == DNSRecordType.MX:
                                        resolution.sections[AUTHORITY_SECTION] = ns_resp.sections[AUTHORITY_SECTION]
                                        print("return here 2")
                                        return resolution
                                    # otherwise try to resolve this server starting from root
                                    else:
                                        # for auth_record in ns_resp.sections[AUTHORITY_SECTION]:
                                        #     auth_resp = self._resolve(domain=auth_record[0].name,
                                        #                               record_type=DNSRecordType.A,
                                        #                               level=0,
                                        #                               nameserver=True)
                                        #     if len(auth_resp.sections[ANSWER_SECTION]) > 0:
                                        #         resolution.sections[ANSWER_SECTION].extend(auth_resp.sections[ANSWER_SECTION])
                                        #         # break
                                        #         print("return here 5")
                                        #         return resolution
                                        print("reaching here")
                                else:
                                    print("return here 6")
                                    return resolution
                                break

                        break
            # break
            print("return at end of root")
            return resolution

        return resolution

    def _query(self, query_domain: str, nameserver: str, record_type: DNSRecordType = DNSRecordType.A,
               level: int = 0) -> dns.message:
        if level > 0:
            subdomain = query_domain.split('.')[-level:]
            query_domain = '.'.join(subdomain)
        query = dns.message.make_query(qname=query_domain, rdtype=record_type.value, want_dnssec=True)
        try:
            if self.use_tcp:
                response = dns.query.tcp(q=query, where=nameserver, timeout=self.timeout)
            else:
                response = dns.query.udp(q=query, where=nameserver, timeout=self.timeout)
            return response
        except Exception as e:
            print("error while getting response for domain: {} from root: {}, ".format(query_domain, nameserver), e)
            return None


if __name__ == "__main__":
    args = sys.argv
    if len(args) != 3:
        print("Enter 2 arguments: domain name and record type")
        exit(0)
    test_domain = args[1]
    record_type = get_record_type(args[2])
    if record_type is None:
        print("Invalid record type: please select A/NS/MX")
        exit(0)
    # test_domain = "dnssec-failed.org"
    # test_domain = "cnn.com"
    # test_domain = "verisigninc.com"
    # record_type = DNSRecordType.A
    myresolver = DNSSecResolver()
    start_time = time.time()
    resp = myresolver.resolve(test_domain, record_type)
    end_time = time.time()
    time_taken = end_time-start_time
    if resp is not None:
        print_dns_response(resp, round(time_taken*1000))


