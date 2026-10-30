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
            self._a_records = {
                self._normalize_name(name): records[0]
                for name, records in parameters["records A"].items()
            }

        if "records NS" in parameters:
            self._ns_records = {
                self._normalize_name(name): records[0]
                for name, records in parameters["records NS"].items()
            }

        if "zones" in parameters:
            self._authoritative_zones = {
                self._normalize_name(zone)
                for zone in parameters["zones"]
            }

    def bind_to_host(self, endhost_id, endhost_ip):
        self._ip = endhost_ip
        
    def _normalize_name(self, name):
        return name.rstrip(".").lower()

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
                    is_authoritative = self._is_authoritative_for(dns_name)
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
        
    def _is_authoritative_for(self, dns_name):
        name = self._normalize_name(dns_name)

        return any(
            name == zone or name.endswith("." + zone)
            for zone in self._authoritative_zones
        )

    def _get_dns_records(self, dns_name):
        answer = []
        authority = []
        additional = []

        normalized_name = self._normalize_name(dns_name)
        record = self._a_records.get(normalized_name)

        if record is not None:
            answer = [
                DnsResourceRecord(
                    dnsName=dns_name,
                    recordType="A",
                    dnsTtl=record["ttl"],
                    rrData=record["ip"]
                )
            ]

        return answer, authority, additional

class LocalNameServer(Application):
    def __init__(self, port):
        super().__init__(port)
        self._ip = None

        self._root_nameserver = None

        self._pending_client_queries = []
        self._outstanding_queries = {}
        self._pending_responses = []

    def bind_to_host(self, endhost_id, endhost_ip):
        self._ip = endhost_ip
        print("LocalNameServer (ip {}, port {}): bind_to_host(endhost_id={}, endhost_ip={})".format(
            self._ip, self._port, endhost_id, endhost_ip))

    def set_parameters(self, parameters):
        self._root_nameserver = parameters["root nameserver"]

        print("LocalNameServer (ip {}, port {}): set_parameters({})".format(
            self._ip, self._port, parameters))

    def _get_query_key(self, packet):
        payload = packet.get_payload()
        header = payload.get_header()
        question = payload.get_question()

        return (
            header.get_query_id(),
            header.get_resolution_id(),
            question.get_dns_name().lower().rstrip(".")
        )

    def process_packet(self, packet):
        print("LocalNameServer (ip {}, port {}): Received packet {}".format(
            self._ip, self._port, packet))

        payload = packet.get_payload()
        header = payload.get_header()

        if header.get_dns_type() == DnsTypes.RESPONSE.value:
            self._pending_responses.append(packet)
        else:
            self._pending_client_queries.append(packet)

    def generate_packets(self):
        outgoing_packets = []

        # Step 1: Forward client queries to the root nameserver.
        for client_query in self._pending_client_queries:
            query_payload = client_query.get_payload()
            query_header = query_payload.get_header()
            question = query_payload.get_question()

            query_key = self._get_query_key(client_query)

            upstream_packet = DnsPacket(
                self._ip,
                self._root_nameserver["ip"]
            )
            upstream_packet.set_destination_port(
                self._root_nameserver["port"]
            )

            upstream_header = DnsHeader(
                queryId=query_header.get_query_id(),
                resolutionId=query_header.get_resolution_id(),
                dnsType=DnsTypes.QUERY.value,
                rd=query_header.get_rd()
            )

            upstream_payload = DnsPayload(
                header=upstream_header,
                question=question,
                answer=[],
                authority=[],
                additional=[]
            )

            upstream_packet.set_payload(upstream_payload)

            self._outstanding_queries[query_key] = client_query

            print("LocalNameServer (ip {}, port {}): Sending upstream query {}".format(
                self._ip, self._port, upstream_packet))

            outgoing_packets.append(upstream_packet)

        self._pending_client_queries = []

        # Step 2: Process responses received from the upstream nameserver.
        for upstream_response in self._pending_responses:
            query_key = self._get_query_key(upstream_response)

            original_query = self._outstanding_queries.pop(query_key, None)

            if original_query is None:
                continue

            original_payload = original_query.get_payload()
            original_header = original_payload.get_header()
            original_question = original_payload.get_question()

            upstream_payload = upstream_response.get_payload()

            # Phase 2 forwards the answer section only.
            answer = upstream_payload.get_answer()

            client_response = DnsPacket(
                self._ip,
                original_query.get_source()
            )

            client_response.set_destination_port(
                original_query.get_source_port()
            )

            response_header = DnsHeader(
                queryId=original_header.get_query_id(),
                resolutionId=original_header.get_resolution_id(),
                dnsType=DnsTypes.RESPONSE.value,
                aa=False,
                rd=original_header.get_rd(),
                ra=True
            )

            response_payload = DnsPayload(
                header=response_header,
                question=original_question,
                answer=answer,
                authority=[],
                additional=[]
            )

            client_response.set_payload(response_payload)

            print("LocalNameServer (ip {}, port {}): Sending response to client {}".format(
                self._ip, self._port, client_response))

            outgoing_packets.append(client_response)

        self._pending_responses = []

        return outgoing_packets

    def update(self, current_time, info_list):
        print("LocalNameServer (ip {}, port {}): update(current_time={}, info_list={})".format(
            self._ip, self._port, current_time, info_list))