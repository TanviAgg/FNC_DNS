import sys
from data import DNSRecordType, ROOT_SERVER_IPS, get_record_type, match_type, print_dns_response, ANSWER_SECTION, \
    AUTHORITY_SECTION, ADDITIONAL_SECTION
import dns.message
import dns.query
from dns.rdatatype import RdataType as RecordType
import time


class DNSResolver:
    def __init__(self, use_tcp=False):
        self.root_server_ips = ROOT_SERVER_IPS
        self.use_tcp = use_tcp
        self.timeout = 5

    def resolve(self, domain: str, record_type: DNSRecordType) -> dns.message:
        return self._resolve(domain, record_type)

    def _resolve(self, domain: str, record_type: DNSRecordType, nameserver: bool = False) -> dns.message:
        # print("resolve domain:", domain)
        resolution = None
        # query root servers for record
        for root_server in self.root_server_ips:
            resolution = self._query(query_domain=domain, nameserver=root_server, record_type=record_type)
            # if this query failed, try other root servers
            if resolution is None:
                continue
            # check if answer is present
            while len(resolution.sections[ANSWER_SECTION]) == 0:
                # ============= ADDITIONAL SECTION ==============
                # process all A type records (ignore AAAA)
                if len(resolution.sections[ADDITIONAL_SECTION]) > 0:
                    for record in resolution.sections[ADDITIONAL_SECTION]:
                        if record[0].rdtype != RecordType.A:
                            continue
                        # try to resolve the given domain using address in record with required type
                        nameserver_address = record[0].address
                        resp = self._query(query_domain=domain, nameserver=nameserver_address, record_type=record_type)
                        # if this query failed, try other records
                        if resp is None:
                            continue
                        # otherwise check answer
                        if len(resp.sections[ANSWER_SECTION]) > 0:
                            if nameserver and resp.sections[ANSWER_SECTION][0].rdtype == RecordType.CNAME:
                                return resp
                            elif resp.sections[ANSWER_SECTION][0].rdtype == RecordType.A:
                                return resp
                        resolution = resp
                        break
                # ============= AUTHORITY SECTION ==============
                # if any nameservers are returned, try to resolve them or else return SOA
                elif len(resolution.sections[AUTHORITY_SECTION]) > 0:
                    for record in resolution.sections[AUTHORITY_SECTION]:
                        # if no additional records are present and we have only SOA,
                        # further resolution is not possible, so return
                        if record[0].rdtype == RecordType.SOA:
                            return resolution
                        # try to resolve the address for authoritative name server starting from root server
                        nameserver_name = record[0].target.to_text()
                        resp = self._resolve(nameserver_name, DNSRecordType.A)
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
                                auth_resp = self._query(query_domain=domain, record_type=record_type,
                                                        nameserver=auth_record[0].address)
                                if auth_resp is None:
                                    continue
                                resolution = auth_resp
                                break
            # ============= ANSWER SECTION ==============
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
                        resp = self._resolve(domain=cname_address, record_type=record_type, nameserver=True)
                        # if this query failed, try other records
                        if resp is None:
                            continue
                        # check answer section
                        if len(resp.sections[ANSWER_SECTION]) == 0:
                            # check authority section if present, sometimes we only get SOA records
                            for c_record in resp.sections[AUTHORITY_SECTION]:
                                if c_record.rdtype == RecordType.SOA:
                                    resolution.sections[AUTHORITY_SECTION] = resp.sections[AUTHORITY_SECTION]
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
                                # otherwise check authority section
                                elif len(ns_resp.sections[AUTHORITY_SECTION]) > 0:
                                    # if we are not looking for A record, add records to main response
                                    if record_type == DNSRecordType.NS or record_type == DNSRecordType.MX:
                                        resolution.sections[AUTHORITY_SECTION] = ns_resp.sections[AUTHORITY_SECTION]
                                        return resolution
                                break
                        break
            return resolution

        return resolution

    def _query(self, query_domain: str, nameserver: str, record_type: DNSRecordType = DNSRecordType.A) -> dns.message:
        query = dns.message.make_query(qname=query_domain, rdtype=record_type.value)
        try:
            if self.use_tcp:
                response = dns.query.tcp(q=query, where=nameserver, timeout=self.timeout)
            else:
                response = dns.query.udp(q=query, where=nameserver, timeout=self.timeout)
            return response
        except Exception as e:
            print("error while getting response for domain: {} from server: {}, ".format(query_domain, nameserver), e)
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
    # test_domain = "www.netflix.com"
    # test_domain = "www.cnn.com"
    # test_domain = "cnn-tls.map.fastly.net"
    # record_type = DNSRecordType.A
    myresolver = DNSResolver()
    start_time = time.time()
    resp = myresolver.resolve(test_domain, record_type)
    end_time = time.time()
    time_taken = end_time-start_time
    print_dns_response(resp, round(time_taken*1000))
