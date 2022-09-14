import sys
from datetime import datetime

from data import DNSRecordType, ROOT_SERVER_IPS
import dns.message
import dns.query
from dns.rdatatype import RdataType as RecordType
import time

QUESTION_SECTION = 0
ANSWER_SECTION = 1
AUTHORITY_SECTION = 2
ADDITIONAL_SECTION = 3


class DNSResolver:
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
            try:
                resolution = self._query(query_domain=domain, nameserver=root_server, record_type=record_type)
                if resolution is not None:
                    # check if answer section is present
                    while len(resolution.sections[ANSWER_SECTION]) == 0:
                        # check additional section
                        # process all A type records (ignore AAAA)
                        if len(resolution.sections[ADDITIONAL_SECTION]) > 0:
                            for record in resolution.sections[ADDITIONAL_SECTION]:
                                if record[0].rdtype != RecordType.A:
                                    continue
                                # try to resolve the given domain using address in record with required type
                                try:
                                    nameserver_address = record[0].address
                                    resp = self._query(query_domain=domain, nameserver=nameserver_address,
                                                       record_type=record_type)
                                    if resp is not None:
                                        if len(resp.sections[ANSWER_SECTION]) > 0:
                                            if nameserver and resp.sections[ANSWER_SECTION][0].rdtype == RecordType.CNAME:
                                                return resp
                                            elif resp.sections[ANSWER_SECTION][0].rdtype == RecordType.A:
                                                return resp
                                        resolution = resp
                                        break
                                except Exception as e:
                                    print("error in response for: {} from server: {}, ".format(domain, record.name), e)
                                    continue

                        # check authority section
                        # if any nameservers are returned, try to resolve them or else return SOA
                        elif len(resolution.sections[AUTHORITY_SECTION]) > 0:
                            for record in resolution.sections[AUTHORITY_SECTION]:
                                # if no additional records are present and we have only SOA,
                                # further resolution is not possible, return
                                if record[0].rdtype == RecordType.SOA:
                                    return resolution
                                # try to resolve the address for authoritative name server starting from root server
                                try:
                                    nameserver_name = record[0].target.to_text()
                                    resp = self._resolve(nameserver_name, DNSRecordType.A, 0)  # CUSTOM DIFF
                                    if resp is not None:
                                        # if we wanted nameserver resolution, return
                                        # else we query the nameserver for given domain
                                        if nameserver:
                                            return resp
                                        elif len(resp.sections[ANSWER_SECTION]) > 0:
                                            for auth_record in resp.sections[ANSWER_SECTION]:
                                                # query the IP address of nameserver for this domain
                                                try:
                                                    auth_resp = self._query(query_domain=domain,
                                                                            record_type=record_type,
                                                                            nameserver=auth_record[0].address)
                                                    resolution = auth_resp
                                                    break
                                                except Exception as e:
                                                    raise e
                                except Exception as e:
                                    print("error in response for: {} from server: {}, ".format(domain, record.name), e)
                                    continue

                    # check answer section
                    # 1. if answer section contains desired record type, return resolution answer
                    # 2. if it contains SOA type record, return answer
                    if len(resolution.sections[ANSWER_SECTION]) > 0:
                        for record in resolution.sections[ANSWER_SECTION]:
                            if record.rdtype == RecordType.A and record_type == DNSRecordType.A:
                                return resolution
                            elif record.rdtype == RecordType.NS and record_type == DNSRecordType.NS:
                                return resolution
                            elif record.rdtype == RecordType.MX and record_type == DNSRecordType.MX:
                                return resolution
                            elif record.rdtype == RecordType.SOA:
                                return resolution
                        # check if CNAME records are present and handle
                        # we need to resolve CNAME further until we get SOA/A records
                        for record in resolution.sections[ANSWER_SECTION]:
                            while record.rdtype == RecordType.CNAME:
                                cname_address = record[0].target.to_text()
                                resp = self._resolve(domain=cname_address, record_type=DNSRecordType.A,
                                                     level=0, nameserver=True)
                                if resp is not None:
                                    for c_record in resp.sections[ANSWER_SECTION]:
                                        # if we got CNAME again, add to the answer to process further
                                        if c_record.rdtype == RecordType.CNAME:
                                            resolution.sections[ANSWER_SECTION].append(c_record)
                                            break
                                        else:
                                            # query server in this record to find CNAME
                                            try:
                                                nameserver_address = c_record[0].address
                                                ns_resp = self._query(query_domain=cname_address,
                                                                      nameserver=nameserver_address,
                                                                      record_type=record_type)
                                                # if we found answer, add it to the main response
                                                if len(ns_resp.sections[ANSWER_SECTION]) > 0:
                                                    resolution.sections[ANSWER_SECTION].extend(
                                                        ns_resp.sections[ANSWER_SECTION])
                                                # otherwise check authority section
                                                elif len(ns_resp.sections[AUTHORITY_SECTION]) > 0:
                                                    # if we are not looking for A record, add records to main response
                                                    if record_type == DNSRecordType.NS or record_type == DNSRecordType.MX:
                                                        resolution.sections[AUTHORITY_SECTION].extend(
                                                            ns_resp.sections[AUTHORITY_SECTION])
                                                    else:
                                                        # try to resolve this server starting from root
                                                        for auth_record in ns_resp.sections[AUTHORITY_SECTION]:
                                                            auth_resp = self._resolve(domain=auth_record[0].name,
                                                                                      record_type=DNSRecordType.A,
                                                                                      level=0,
                                                                                      nameserver=True)
                                                            if len(auth_resp.sections[ANSWER_SECTION]) > 0:
                                                                resolution.sections[ANSWER_SECTION].extend(
                                                                    auth_resp.sections[ANSWER_SECTION])
                                                                break
                                                break
                                            except Exception as e:
                                                raise e
                                break
                break
            except Exception as e:
                print("error while getting response for domain: {} from root: {}, ".format(domain, root_server), e)
                continue

        return resolution

    def _query(self, query_domain: str, nameserver: str, record_type: DNSRecordType = DNSRecordType.A,
               level: int = 0) -> dns.message:
        if level > 0:
            subdomain = query_domain.split('.')[-level:]
            query_domain = '.'.join(subdomain)
        query = dns.message.make_query(qname=query_domain, rdtype=record_type.value)
        try:
            if self.use_tcp:
                response = dns.query.tcp(q=query, where=nameserver, timeout=self.timeout)
            else:
                response = dns.query.udp(q=query, where=nameserver, timeout=self.timeout)
            return response
        except Exception as e:
            raise e

    def print_dns_response(self, response: dns.message, query_time: int):
        print("QUESTION SECTION:")
        print(response.sections[QUESTION_SECTION][0].to_text())
        print("")
        if len(response.sections[ANSWER_SECTION]) > 0:
            print("ANSWER SECTION:")
            for record in response.sections[ANSWER_SECTION]:
                print(record.to_text())
            print("")
        if len(response.sections[AUTHORITY_SECTION]) > 0:
            print("AUTHORITY SECTION:")
            for record in response.sections[AUTHORITY_SECTION]:
                print(record.to_text())
            print("")
        print("QUERY TIME: {} msec".format(round(query_time*1000)))
        print("WHEN: ", datetime.today())
        print("MSG SIZE rcvd: ", sys.getsizeof(response.to_text()))


if __name__ == "__main__":
    test_domain = "tmail.com"
    test_type = DNSRecordType.A
    myresolver = DNSResolver()
    start_time = time.time()
    resp = myresolver.resolve(test_domain, test_type)
    end_time = time.time()

    myresolver.print_dns_response(resp, end_time-start_time)

