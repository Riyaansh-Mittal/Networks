from endhost_application import ClientApplication
from packet import Packet, PacketTypes, DnsPacket, DnsPayload, DnsHeader, DnsQuestion, DnsTypes
from utils import Formatter

class SenderApplication(ClientApplication):
    def __init__(self, port):
        super().__init__(port)
        self._src_ip = None
        self._dest_ip = None
        self._num_packets_to_send = 0
        self._packets_sent = 0

    def trigger_send(self, args):
        dest_ip = args[0]
        dst_port = args[1]
        num_packets = args[2]
        self._dest_ip = dest_ip
        self._dst_port = dst_port
        self._num_packets_to_send += num_packets

    def bind_to_host(self, endhost_id, endhost_ip):
        self._src_ip = endhost_ip

    def process_packet(self, packet):
        print("SenderApplication (ip {}, port {}): Received packet {}".format(self._src_ip, self._port, str(packet)))

    def generate_packets(self):
        packets = []
        if self._src_ip and self._dest_ip and self._packets_sent < self._num_packets_to_send:
            pkt = Packet(self._src_ip, self._dest_ip)
            pkt.set_type(PacketTypes.DATA.value)
            pkt.set_destination_port(self._dst_port)
            packets.append(pkt)
            self._packets_sent += 1
            print("SenderApplication (ip {}, port {}): Generating packet {} from {} to {} (dest port {})".format(self._src_ip, self._port, self._packets_sent, self._src_ip, self._dest_ip, self._dst_port))
        return packets

class SinkApplication(ClientApplication):
    def __init__(self, port):
        super().__init__(port)
        self._ip = None

    def bind_to_host(self, endhost_id, endhost_ip):
        self._ip = endhost_ip

    def process_packet(self, packet):
        print("SinkApplication (ip {}, port {}): Received packet {}".format(self._ip, self._port, str(packet)))

    def generate_packets(self):
        return []

class DnsClient(ClientApplication):
    def __init__(self, port):
        super().__init__(port)
        self._endhost_id = None
        self._endhost_ip = None
        self._pending_queries = []   # list of query-param dicts awaiting a packet
        self._query_id_counter = 0

    def process_packet(self, packet):
        if not isinstance(packet, DnsPacket):
            print("DnsClient (ip {}, port {}): Received non-DNS packet {}".format(self._endhost_ip, self._port, packet))
            return

        if packet.get_payload().get_header().get_dns_type() != DnsTypes.RESPONSE.value:
            print("DnsClient (ip {}, port {}): ERROR expected a DNS reply but got {}".format(self._endhost_ip, self._port, packet))
        else:
            Formatter.print_dig_output(packet)

    def generate_packets(self):
        packets = []
        for query_params in self._pending_queries:
            self._query_id_counter += 1
            packet = self._create_query(query_params, self._query_id_counter)
            print("DnsClient (ip {}, port {}): Sending packet {}".format(self._endhost_ip, self._port, packet))
            packets.append(packet)
        self._pending_queries = []
        return packets

    def bind_to_host(self, endhost_id, endhost_ip):
        self._endhost_id = endhost_id
        self._endhost_ip = endhost_ip

    def trigger_send(self, args):
        dst, dst_port, dnsName, questionType = args
        self._pending_queries.append({
            'dst': dst,
            'dst_port': dst_port,
            'dnsName': dnsName,
            'questionType': questionType,
        })

    def _create_query(self, query_params, queryId):
        if self._endhost_ip is None:
            raise Exception("DnsClient must be bound to a host before creating queries.")

        packet = DnsPacket(self._endhost_ip, query_params['dst'])
        packet.set_source_port(self._port)
        packet.set_destination_port(query_params['dst_port'])
        header = DnsHeader(
            queryId=queryId,
            dnsType=query_params.get('dnsType', DnsTypes.QUERY.value),
            resolutionId="{}:{}/{}".format(self._endhost_id,self._port,self._query_id_counter),
            aa=False,
            rd=True,
            ra=False
        )
        question = DnsQuestion(
            dnsName=query_params.get('dnsName'),
            questionType=query_params.get('questionType')
        )
        payload = DnsPayload(header=header, question=question)
        packet.set_payload(payload)
        return packet

class ContentClient(ClientApplication):
    def __init__(self, port):
        super().__init__(port)
        self._endhost_id = None
        self._endhost_ip = None
        self._pending_queries = []       # list of query-param dicts awaiting a packet (and a new session, once one is sent - see generate_packets)
        self._query_id_counter = 0
        self._pending_answers = []       # list of (session_id, [DnsResourceRecord, ...]) received since the last generate_packets() call, awaiting caching
        self._sessions = {}              # dict: session_id -> {"dnsName", "query_params", "start_time", "duration", "load", "entries"} - one per "accesscontent" trigger, see trigger_access_content/generate_packets/_renew_expired_sessions/_prune_terminated_sessions
        self._session_id_counter = 0
        self._session_by_query_id = {}   # dict: queryId -> session_id - correlates an incoming reply back to whichever session sent the query it answers, see process_packet/_send_query
        self._current_time = None        # most recent time reported via update() - generate_packets() has no time parameter of its own, so it relies on this instead (see update() below)

    def update(self, current_time, info_list):
        self._current_time = current_time

    def process_packet(self, packet):
        if not isinstance(packet, DnsPacket):
            print("ContentClient (ip {}, port {}): Received non-DNS packet {}".format(self._endhost_ip, self._port, packet))
            return

        if packet.get_payload().get_header().get_dns_type() != DnsTypes.RESPONSE.value:
            print("ContentClient (ip {}, port {}): ERROR expected a DNS reply but got {}".format(self._endhost_ip, self._port, packet))
        else:
            question = packet.get_payload().get_question()
            intro_line = "ContentClient (ip {}, port {}): Received DNS reply for queried name {}".format(
                packet.get_destination(), packet.get_destination_port(), question.dnsName)
            Formatter.print_dig_output(packet, intro_line=intro_line)
            answer = packet.get_payload().get_answer()
            if answer:
                session_id = self._session_by_query_id.get(packet.get_payload().get_header().get_query_id())
                if session_id is not None:
                    self._pending_answers.append((session_id, answer))

    def generate_packets(self):
        time = self._current_time
        for session_id, records in self._pending_answers:
            self._cache_answer(session_id, records, time)
        self._pending_answers = []

        packets = []
        for query_params in self._pending_queries:
            session_id = self._session_id_counter
            self._session_id_counter += 1
            self._sessions[session_id] = {
                'dnsName': query_params['dnsName'],
                'query_params': query_params,
                'start_time': time,
                'duration': query_params['duration'],
                'load': query_params['load'],
                'entries': None,  # known-but-unresolved as soon as the query goes out, so ContentClientRevenueChecker can already account for it having no resolved path yet
                'latest_query_id': None,  # set by _send_query, right below, before generate_packets() returns - see get_cached_ips_by_session/get_pending_query_ids
            }
            packets.append(self._send_query(query_params, session_id))
        self._pending_queries = []

        packets += self._renew_expired_sessions(time)
        self._prune_terminated_sessions(time)
        return packets

    def _send_query(self, query_params, session_id):
        self._query_id_counter += 1
        self._session_by_query_id[self._query_id_counter] = session_id
        session = self._sessions.get(session_id)
        if session is not None:
            session['latest_query_id'] = self._query_id_counter
        packet = self._create_query(query_params, self._query_id_counter)
        print("ContentClient (ip {}, port {}): Sending packet {}".format(self._endhost_ip, self._port, packet))
        return packet

    def _is_session_live(self, session, time):
        return time < session['start_time'] + session['duration']

    def _get_live_entries(self, session, time):
        entries = session.get('entries')
        if not entries:
            return {}
        valid = {ip: e for ip, e in entries.items() if time - e["cached_at"] < e["ttl"]}
        if not valid:
            session['entries'] = None
        elif len(valid) != len(entries):
            session['entries'] = valid
        return valid

    def _renew_expired_sessions(self, time):
        packets = []
        for session_id, session in list(self._sessions.items()):
            if not self._is_session_live(session, time):
                continue
            if session['entries'] is None:
                continue
            if self._get_live_entries(session, time):
                continue  # still has at least one valid IP - nothing to renew
            packets.append(self._send_query(session['query_params'], session_id))
        return packets

    def _prune_terminated_sessions(self, time):
        for session_id in [sid for sid, s in self._sessions.items() if not self._is_session_live(s, time)]:
            del self._sessions[session_id]

    def _cache_answer(self, session_id, records, time):
        session = self._sessions.get(session_id)
        if session is None:
            return  # this session was already pruned (its duration window closed) before its reply arrived - nothing to cache
        dns_name = session['dnsName']
        load = session['load']
        address_records = [record for record in records if record.get_record_type() == "A"]
        num_records = len(address_records)
        base_share = load // num_records if num_records else 0
        remainder = load % num_records if num_records else 0

        entries = {}
        for i, record in enumerate(address_records):
            share = base_share + (1 if i < remainder else 0)
            ip = record.get_rr_data()
            if share > 0:
                entries[ip] = {"ttl": record.get_dns_ttl(), "cached_at": time, "load": share, "recordName": record.get_dns_name()}
                if self._verbose:
                    print("ContentClient (ip {}, port {}): caching {} -> {} (load {}) for {} step(s)".format(
                        self._endhost_ip, self._port, dns_name, ip, share, record.get_dns_ttl()))
            elif self._verbose:
                print("ContentClient (ip {}, port {}): not caching {} -> {} - assigned load 0".format(
                    self._endhost_ip, self._port, dns_name, ip))
        session['entries'] = entries or None

    def _get_cached_ips(self, dns_name, time):
        result = {}
        for session in self._sessions.values():
            if session['dnsName'] != dns_name or not self._is_session_live(session, time):
                continue
            for ip, entry in self._get_live_entries(session, time).items():
                result[ip] = result.get(ip, 0) + entry["load"]
        return result

    def _get_cached_ip(self, dns_name, time):
        ips = self._get_cached_ips(dns_name, time)
        return next(iter(ips), None)

    def get_cached_ips_by_session(self, dns_name, time):
        result = {}
        for session in self._sessions.values():
            if session['dnsName'] != dns_name or not self._is_session_live(session, time):
                continue
            entries = self._get_live_entries(session, time)
            if entries:
                result[session['latest_query_id']] = {
                    ip: {"load": e["load"], "recordName": e["recordName"]} for ip, e in entries.items()
                }
        return result

    def get_queried_names(self):
        return list({session['dnsName'] for session in self._sessions.values()})

    def get_known_ips(self, time):
        known = {}
        for dns_name in self.get_queried_names():
            ip = self._get_cached_ip(dns_name, time)
            if ip is not None:
                known[dns_name] = ip
        return known

    def get_pending_names(self, time):
        return [dns_name for dns_name in self.get_queried_names() if self._get_cached_ip(dns_name, time) is None]

    def get_pending_query_ids(self, dns_name, time):
        return [
            session['latest_query_id']
            for session in self._sessions.values()
            if session['dnsName'] == dns_name and self._is_session_live(session, time)
            and not self._get_live_entries(session, time)
        ]

    def bind_to_host(self, endhost_id, endhost_ip):
        self._endhost_id = endhost_id
        self._endhost_ip = endhost_ip

    def trigger_access_content(self, args):
        dst, dst_port, dnsName, questionType, load, duration = args
        self._pending_queries.append({
            'dst': dst,
            'dst_port': dst_port,
            'dnsName': dnsName,
            'questionType': questionType,
            'load': load,
            'duration': duration,
        })

    def get_query_load(self, dns_name):
        return sum(session['load'] for session in self._sessions.values() if session['dnsName'] == dns_name)

    def get_session_id(self, query_id):
        return self._session_by_query_id.get(query_id)

    def _create_query(self, query_params, queryId):
        if self._endhost_ip is None:
            raise Exception("ContentClient must be bound to a host before creating queries.")

        packet = DnsPacket(self._endhost_ip, query_params['dst'])
        packet.set_source_port(self._port)
        packet.set_destination_port(query_params['dst_port'])
        header = DnsHeader(
            queryId=queryId,
            dnsType=query_params.get('dnsType', DnsTypes.QUERY.value),
            resolutionId="{}:{}/{}".format(self._endhost_id,self._port,self._query_id_counter),
            aa=False,
            rd=True,
            ra=False
        )
        question = DnsQuestion(
            dnsName=query_params.get('dnsName'),
            questionType=query_params.get('questionType')
        )
        payload = DnsPayload(header=header, question=question)
        packet.set_payload(payload)
        return packet
