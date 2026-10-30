from endhost_application import Application
from packet import DnsPacket, DnsPayload, DnsHeader, DnsResourceRecord, DnsTypes

class AuthoritativeNameServer(Application):
    def __init__(self, port):
        super().__init__(port)
        self._ip = None
        self._a_records = {}
        self._ns_records = {}
        self._authoritative_zones = set()
        self._pending_queries = []

    def set_parameters(self, parameters):
        if "records A" in parameters:
            self._a_records = {name: records[0] for name, records in parameters["records A"].items()}
        if "records NS" in parameters:
            self._ns_records = {name: records[0] for name, records in parameters["records NS"].items()}
        if "zones" in parameters:
            self._authoritative_zones = set(parameters["zones"])

    def bind_to_host(self, endhost_id, endhost_ip):
        self._ip = endhost_ip

    def process_packet(self, packet):
        print("AuthoritativeNameServer (ip {}, port {}): Received packet {}".format(self._ip, self._port, str(packet)))
        self._pending_queries.append(packet)

    def generate_packets(self):
        replies = []
        for query_pkt in self._pending_queries:
            reply_pkt = DnsPacket(self._ip, query_pkt.get_source())
            reply_pkt.set_destination_port(query_pkt.get_source_port())
            
            query_payload = query_pkt.get_payload()
            query_header = query_payload.get_header()
            query_question = query_payload.get_question()
            dns_name = query_question.get_dns_name()
            
            is_authoritative = False
            for zone in self._authoritative_zones:
                if dns_name.endswith(zone):
                    is_authoritative = True
                    break

            reply_header = DnsHeader(
                queryId=query_header.get_query_id(),
                resolutionId=query_header.get_resolution_id(),
                dnsType=DnsTypes.RESPONSE.value,
                aa=is_authoritative,
                rd=query_header.get_rd(),
                ra=False
            )
            
            (answer, authority, additional) = self._get_dns_records(dns_name)
            reply_payload = DnsPayload(header=reply_header, question=query_question, answer=answer, authority=authority, additional=additional)
            reply_pkt.set_payload(reply_payload)
            
            print("AuthoritativeNameServer (ip {}, port {}): Sending packet {}".format(self._ip, self._port, reply_pkt))
            replies.append(reply_pkt)
        
        self._pending_queries = []
        return replies

    def _get_dns_records(self, dns_name):
        answer = []
        authority = []
        additional = []
        if dns_name in self._a_records:
            record = self._a_records[dns_name]
            answer = [DnsResourceRecord(dnsName=dns_name, recordType="A", dnsTtl=record["ttl"], rrData=record["ip"])]
        return (answer, authority, additional)

class LocalNameServer(Application):
    def __init__(self, port):
        super().__init__(port)
        self._ip = None

    def bind_to_host(self, endhost_id, endhost_ip):
        self._ip = endhost_ip
        print("LocalNameServer (ip {}, port {}): bind_to_host(endhost_id={}, endhost_ip={})".format(
            self._ip, self._port, endhost_id, endhost_ip))

    def set_parameters(self, parameters):
        print("LocalNameServer (ip {}, port {}): set_parameters({})".format(self._ip, self._port, parameters))

    def process_packet(self, packet):
        print("LocalNameServer (ip {}, port {}): process_packet({})".format(self._ip, self._port, packet))

    def generate_packets(self):
        print("LocalNameServer (ip {}, port {}): generate_packets()".format(self._ip, self._port))
        return []

    def update(self, current_time, info_list):
        print("LocalNameServer (ip {}, port {}): update(current_time={}, info_list={})".format(
            self._ip, self._port, current_time, info_list))
