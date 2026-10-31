from endhost_application import Application
from packet import (
    DnsPacket,
    DnsPayload,
    DnsHeader,
    DnsQuestion,
    DnsResourceRecord,
    DnsTypes,
    DnsStatusCodes,
)


class AuthoritativeNameServer(Application):
    """A small authoritative server supporting A, CNAME and referrals."""

    def __init__(self, port):
        super().__init__(port)
        self._ip = None
        self._a_records = {}
        self._cname_records = {}
        self._ns_records = {}
        self._authoritative_zones = set()
        self._pending_queries = []

    @staticmethod
    def _normalize_name(name):
        if name is None:
            return ""
        name = name.lower()
        return "." if name == "." else name.rstrip(".")

    @staticmethod
    def _display_name(name):
        if name == ".":
            return "."
        return name.rstrip(".") + "."

    def set_parameters(self, parameters):
        self._a_records = {
            self._normalize_name(name): list(records)
            for name, records in parameters.get("records A", {}).items()
        }
        self._cname_records = {
            self._normalize_name(name): list(records)
            for name, records in parameters.get("records CNAME", {}).items()
        }
        self._ns_records = {
            self._normalize_name(name): list(records)
            for name, records in parameters.get("records NS", {}).items()
        }
        self._authoritative_zones = {
            self._normalize_name(zone)
            for zone in parameters.get("zones", [])
        }

    def bind_to_host(self, endhost_id, endhost_ip):
        self._ip = endhost_ip

    def process_packet(self, packet):
        payload = packet.get_payload()
        header = payload.get_header()
        if header is not None and header.get_dns_type() == DnsTypes.QUERY.value:
            self._pending_queries.append(packet)

    def _is_within_zone(self, dns_name, zone):
        name = self._normalize_name(dns_name)
        zone = self._normalize_name(zone)
        if zone == ".":
            return True
        return name == zone or name.endswith("." + zone)

    def _get_most_specific_zone(self, dns_name):
        zones = [z for z in self._authoritative_zones
                 if self._is_within_zone(dns_name, z)]
        return max(zones, key=lambda z: (z.count("."), len(z)), default=None)

    def _is_authoritative_for(self, dns_name):
        return self._get_most_specific_zone(dns_name) is not None

    def _get_glue_record(self, ns_record):
        if ns_record.get("ip") is None or ns_record.get("ipttl") is None:
            return None
        return DnsResourceRecord(
            dnsName=self._display_name(self._normalize_name(ns_record["name"])),
            recordType="A",
            dnsTtl=ns_record["ipttl"],
            rrData=ns_record["ip"],
        )

    def _get_dns_records(self, dns_name):
        answer, authority, additional = [], [], []
        name = self._normalize_name(dns_name)
        selected_zone = self._get_most_specific_zone(name)
        if selected_zone is None:
            return answer, authority, additional

        # A child-zone delegation takes precedence over any parent-zone data
        # below that cut. The parent must not answer for names delegated away.
        delegations = [d for d in self._ns_records
                       if d != selected_zone
                       and self._is_within_zone(name, d)
                       and self._is_within_zone(d, selected_zone)]
        if delegations:
            delegation = max(delegations, key=lambda d: (d.count("."), len(d)))
            for ns in self._ns_records[delegation]:
                glue = self._get_glue_record(ns)
                if glue is None:
                    continue
                authority.append(DnsResourceRecord(
                    dnsName=self._display_name(delegation), recordType="NS",
                    dnsTtl=ns["namettl"],
                    rrData=self._display_name(self._normalize_name(ns["name"]))
                ))
                additional.append(glue)
            return answer, authority, additional

        # Exact A records take precedence only when no child delegation applies.
        for record in self._a_records.get(name, []):
            answer.append(DnsResourceRecord(
                dnsName=self._display_name(name), recordType="A",
                dnsTtl=record["ttl"], rrData=record["ip"]
            ))
        if answer:
            return answer, authority, additional

        # Return CNAME(s). Include target A data only when this server is
        # authoritative for the target too; otherwise the resolver follows it.
        cname_records = self._cname_records.get(name, [])
        if cname_records:
            for record in cname_records:
                target = self._normalize_name(record["alias"])
                answer.append(DnsResourceRecord(
                    dnsName=self._display_name(name), recordType="CNAME",
                    dnsTtl=record["ttl"], rrData=self._display_name(target)
                ))
                if self._is_authoritative_for(target):
                    for target_record in self._a_records.get(target, []):
                        answer.append(DnsResourceRecord(
                            dnsName=self._display_name(target), recordType="A",
                            dnsTtl=target_record["ttl"], rrData=target_record["ip"]
                        ))
            return answer, authority, additional

        return answer, authority, additional

    def generate_packets(self):
        replies = []
        for query_pkt in self._pending_queries:
            payload = query_pkt.get_payload()
            query_header = payload.get_header()
            question = payload.get_question()
            answer, authority, additional = self._get_dns_records(
                question.get_dns_name()
            )
            reply = DnsPacket(self._ip, query_pkt.get_source())
            reply.set_destination_port(query_pkt.get_source_port())
            reply.set_payload(DnsPayload(
                header=DnsHeader(
                    queryId=query_header.get_query_id(),
                    resolutionId=query_header.get_resolution_id(),
                    dnsType=DnsTypes.RESPONSE.value,
                    aa=(self._is_authoritative_for(question.get_dns_name())
                        and not authority),
                    rd=query_header.get_rd(),
                    ra=False,
                ),
                question=question,
                answer=answer,
                authority=authority,
                additional=additional,
            ))
            replies.append(reply)
        self._pending_queries = []
        return replies


class LocalNameServer(Application):
    """Recursive resolver with TTL-aware answer and referral caches."""

    def __init__(self, port):
        super().__init__(port)
        self._ip = None
        self._root_nameserver = None
        self._pending_client_queries = []
        self._outstanding_queries = {}
        self._pending_responses = []
        self._upstream_responses = []
        self._cache = {}
        self._referral_cache = {}
        self._current_time = 0
        # Simulation time is advanced once per end-host iteration. A query
        # unanswered for this many ticks is treated as a failed nameserver.
        self._nameserver_timeout = 6

    @staticmethod
    def _normalize_name(name):
        if name is None:
            return ""
        name = name.lower()
        return "." if name == "." else name.rstrip(".")

    @staticmethod
    def _display_name(name):
        if name == ".":
            return "."
        return name.rstrip(".") + "."

    def bind_to_host(self, endhost_id, endhost_ip):
        self._ip = endhost_ip

    def set_parameters(self, parameters):
        self._root_nameserver = parameters["root nameserver"]

    def update(self, current_time, info_list):
        self._current_time = current_time

    def _get_query_key(self, packet):
        payload = packet.get_payload()
        header = payload.get_header()
        question = payload.get_question()
        return (header.get_resolution_id(), header.get_query_id(),
                self._normalize_name(question.get_dns_name()),
                question.get_question_type())

    def _get_cache_key(self, name, question_type="A"):
        return self._normalize_name(name), question_type

    @staticmethod
    def _copy_record_with_ttl(record, ttl):
        return DnsResourceRecord(
            dnsName=record.get_dns_name(),
            recordType=record.get_record_type(),
            dnsTtl=max(0, int(ttl)),
            rrData=record.get_rr_data(),
        )

    def _make_expiring_entries(self, records):
        entries = []
        for record in records:
            ttl = record.get_dns_ttl()
            if ttl is None or ttl <= 0:
                continue
            entries.append({"record": record, "expiry": self._current_time + ttl})
        return entries

    def _records_from_entries(self, entries):
        records = []
        for entry in entries:
            remaining = entry["expiry"] - self._current_time
            if remaining > 0:
                records.append(self._copy_record_with_ttl(entry["record"], remaining))
        return records

    def _cache_response(self, key, answer_entries, authority_entries,
                        additional_entries):
        self._cache[key] = {
            "answer": answer_entries,
            "authority": authority_entries,
            "additional": additional_entries,
        }

    def _get_cached_response(self, key):
        cached = self._cache.get(key)
        if cached is None:
            return None
        answer = self._records_from_entries(cached["answer"])
        if not answer:
            self._cache.pop(key, None)
            return None
        # A cached CNAME chain is only useful while every link in the chain
        # remains valid. Never return a target A record after its alias CNAME
        # has expired (or vice versa).
        has_cname = any(
            entry["record"].get_record_type() == "CNAME"
            for entry in cached["answer"]
        )
        if has_cname and len(answer) != len(cached["answer"]):
            self._cache.pop(key, None)
            return None
        authority = self._records_from_entries(cached["authority"])
        additional = self._records_from_entries(cached["additional"])
        # Remove orphaned NS records if their glue has expired.
        authority, additional = self._pair_referral_records(authority, additional)
        return answer, authority, additional

    @staticmethod
    def _pair_referral_records(authority, additional):
        paired_ns, paired_glue = [], []
        used = set()
        for ns in authority:
            if ns.get_record_type() != "NS":
                continue
            target = LocalNameServer._normalize_name(ns.get_rr_data())
            for index, glue in enumerate(additional):
                if index in used or glue.get_record_type() != "A":
                    continue
                if LocalNameServer._normalize_name(glue.get_dns_name()) == target:
                    paired_ns.append(ns)
                    paired_glue.append(glue)
                    used.add(index)
                    break
        return paired_ns, paired_glue

    def _get_referral_records(self, response):
        payload = response.get_payload()
        return self._pair_referral_records(
            payload.get_authority(), payload.get_additional()
        )

    def _update_best_referral(self, state, authority, additional):
        authority, additional = self._pair_referral_records(authority, additional)
        if not authority:
            return

        queried_name = self._normalize_name(state["current_name"])
        zone = self._normalize_name(authority[0].get_dns_name())
        if not self._is_within_zone(queried_name, zone):
            return

        valid_authority, valid_additional = [], []
        for ns, glue in zip(authority, additional):
            if self._normalize_name(ns.get_dns_name()) != zone:
                continue
            if self._normalize_name(ns.get_rr_data()) != self._normalize_name(glue.get_dns_name()):
                continue
            ns_ttl, glue_ttl = ns.get_dns_ttl(), glue.get_dns_ttl()
            if ns_ttl is None or glue_ttl is None or ns_ttl <= 0 or glue_ttl <= 0:
                continue
            valid_authority.append(ns)
            valid_additional.append(glue)

        if not valid_authority:
            return
        current_zone = state["best_zone"]
        if current_zone is not None and not self._is_within_zone(zone, current_zone):
            return
        state["best_zone"] = zone
        state["best_authority_entries"] = self._make_expiring_entries(valid_authority)
        state["best_additional_entries"] = self._make_expiring_entries(valid_additional)

    def _is_within_zone(self, name, zone):
        name = self._normalize_name(name)
        zone = self._normalize_name(zone)
        if zone == ".":
            return True
        return name == zone or name.endswith("." + zone)

    def _cache_referral(self, authority, additional, queried_name=None):
        authority, additional = self._pair_referral_records(
            authority, additional
        )

        if not authority:
            return

        zone = self._normalize_name(authority[0].get_dns_name())
        if any(self._normalize_name(ns.get_dns_name()) != zone for ns in authority):
            return

        if queried_name is not None:
            queried_name = self._normalize_name(queried_name)

            if not self._is_within_zone(queried_name, zone):
                return

        pairs = []

        for ns, glue in zip(authority, additional):
            ns_zone = self._normalize_name(ns.get_dns_name())
            ns_target = self._normalize_name(ns.get_rr_data())
            glue_name = self._normalize_name(glue.get_dns_name())

            if ns_zone != zone or ns_target != glue_name:
                continue

            ns_ttl = ns.get_dns_ttl()
            glue_ttl = glue.get_dns_ttl()

            if ns_ttl is None or glue_ttl is None:
                continue

            if ns_ttl <= 0 or glue_ttl <= 0:
                continue

            pairs.append({
                "authority": {
                    "record": ns,
                    "expiry": self._current_time + ns_ttl,
                },
                "additional": {
                    "record": glue,
                    "expiry": self._current_time + glue_ttl,
                },
                "ip": glue.get_rr_data(),
                "port": 53,
            })

        if pairs:
            self._referral_cache[zone] = {"pairs": pairs}

    def _get_cached_referral(self, dns_name):
        name = self._normalize_name(dns_name)
        matches = []
        for zone, entry in list(self._referral_cache.items()):
            live_pairs = []
            for pair in entry["pairs"]:
                ns_ttl = pair["authority"]["expiry"] - self._current_time
                glue_ttl = pair["additional"]["expiry"] - self._current_time
                if ns_ttl > 0 and glue_ttl > 0:
                    live_pairs.append(pair)
            if not live_pairs:
                del self._referral_cache[zone]
                continue
            entry["pairs"] = live_pairs
            if self._is_within_zone(name, zone):
                matches.append((zone, entry))
        if not matches:
            return None
        zone, entry = max(matches, key=lambda item: (item[0].count("."), len(item[0])))
        authority, additional, nameservers = [], [], []
        for pair in entry["pairs"]:
            ns_ttl = pair["authority"]["expiry"] - self._current_time
            glue_ttl = pair["additional"]["expiry"] - self._current_time
            authority.append(self._copy_record_with_ttl(pair["authority"]["record"], ns_ttl))
            additional.append(self._copy_record_with_ttl(pair["additional"]["record"], glue_ttl))
            nameservers.append({"ip": pair["ip"], "port": pair["port"]})
        return {"zone": zone, "authority": authority,
                "additional": additional, "nameservers": nameservers}

    def _create_client_response(self, original_query, answer,
                                authority=None, additional=None,
                                status_code=DnsStatusCodes.NOERROR.value):
        original_payload = original_query.get_payload()
        original_header = original_payload.get_header()

        packet = DnsPacket(self._ip, original_query.get_source())
        packet.set_destination_port(original_query.get_source_port())

        packet.set_payload(DnsPayload(
            header=DnsHeader(
                queryId=original_header.get_query_id(),
                resolutionId=original_header.get_resolution_id(),
                dnsType=DnsTypes.RESPONSE.value,
                aa=False,
                rd=original_header.get_rd(),
                ra=True,
                statusCode=status_code,
            ),
            question=original_payload.get_question(),
            answer=answer,
            authority=authority or [],
            additional=additional or [],
        ))

        return packet

    def _create_upstream_query(self, original_query, dns_name,
                               nameserver_ip, nameserver_port):
        original_header = original_query.get_payload().get_header()
        question = DnsQuestion(
            dnsName=self._display_name(self._normalize_name(dns_name)),
            questionType="A",
        )
        packet = DnsPacket(self._ip, nameserver_ip)
        packet.set_destination_port(nameserver_port)
        packet.set_payload(DnsPayload(
            header=DnsHeader(
                queryId=original_header.get_query_id(),
                resolutionId=original_header.get_resolution_id(),
                dnsType=DnsTypes.QUERY.value,
                rd=False,
            ),
            question=question,
            answer=[], authority=[], additional=[],
        ))
        return packet

    def _finish_resolution(self, state, outgoing_packets,
                        status_code=DnsStatusCodes.NOERROR.value):
        answer = self._records_from_entries(state["answer_entries"])
        authority = self._records_from_entries(state["best_authority_entries"])
        additional = self._records_from_entries(state["best_additional_entries"])

        authority, additional = self._pair_referral_records(
            authority, additional
        )

        # Cache only successful responses.
        if status_code == DnsStatusCodes.NOERROR.value and answer:
            key = self._get_cache_key(
                state["client_query"].get_payload().get_question().get_dns_name(),
                state["client_query"].get_payload().get_question().get_question_type(),
            )

            self._cache_response(
                key,
                list(state["answer_entries"]),
                list(state["best_authority_entries"]),
                list(state["best_additional_entries"]),
            )

        outgoing_packets.append(self._create_client_response(
            state["client_query"],
            answer if status_code == DnsStatusCodes.NOERROR.value else [],
            authority,
            additional,
            status_code,
        ))

    def _send_query_to_nameserver(self, state, dns_name, nameserver_ip,
                                  nameserver_port, outgoing_packets):
        key = (nameserver_ip, nameserver_port)
        if key in state["visited_nameservers"]:
            return False
        state["visited_nameservers"].add(key)
        state["current_name"] = self._normalize_name(dns_name)
        packet = self._create_upstream_query(
            state["client_query"], state["current_name"],
            nameserver_ip, nameserver_port,
        )
        self._outstanding_queries[self._get_query_key(packet)] = {
            "state": state,
            "sent_at": self._current_time,
            "nameserver": key,
        }
        outgoing_packets.append(packet)
        return True

    def _start_resolution(self, client_query, outgoing_packets):
        question = client_query.get_payload().get_question()
        name = self._normalize_name(question.get_dns_name())
        state = {
            "client_query": client_query,
            "current_name": name,
            "visited_nameservers": set(),
            "fallback_nameservers": [],
            "visited_cnames": {name},
            "cname_hops": 0,
            "answer_entries": [],
            "best_zone": None,
            "best_authority_entries": [],
            "best_additional_entries": [],
        }
        referral = self._get_cached_referral(name)
        if referral is not None:
            state["fallback_nameservers"] = list(referral["nameservers"])
            self._update_best_referral(
                state, referral["authority"], referral["additional"]
            )
            if self._send_next_nameserver(state, name, outgoing_packets):
                return
        self._send_query_to_nameserver(
            state, name, self._root_nameserver["ip"],
            self._root_nameserver["port"], outgoing_packets,
        )

    def _send_next_nameserver(self, state, dns_name, outgoing_packets):
        """Try the next unvisited nameserver from the current referral."""
        while state["fallback_nameservers"]:
            ns = state["fallback_nameservers"].pop(0)
            if self._send_query_to_nameserver(
                state, dns_name, ns["ip"], ns["port"], outgoing_packets
            ):
                return True
        return False

    def _follow_cname(self, state, cname_records, outgoing_packets):
        targets = {
            self._normalize_name(record.get_rr_data())
            for record in cname_records
        }

        if len(targets) != 1:
            self._finish_resolution(
                state, outgoing_packets, DnsStatusCodes.SERVFAIL.value
            )
            return

        target = next(iter(targets))

        if not target or target in state["visited_cnames"]:
            self._finish_resolution(
                state, outgoing_packets, DnsStatusCodes.SERVFAIL.value
            )
            return

        state["cname_hops"] = state.get("cname_hops", 0) + 1

        if state["cname_hops"] > 16:
            self._finish_resolution(
                state, outgoing_packets, DnsStatusCodes.SERVFAIL.value
            )
            return

        state["visited_cnames"].add(target)
        state["current_name"] = target

        state["best_zone"] = None
        state["best_authority_entries"] = []
        state["best_additional_entries"] = []
        state["visited_nameservers"] = set()
        state["fallback_nameservers"] = []

        referral = self._get_cached_referral(target)

        if referral is not None:
            state["fallback_nameservers"] = list(referral["nameservers"])

            self._update_best_referral(
                state,
                referral["authority"],
                referral["additional"]
            )

            if self._send_next_nameserver(
                state, target, outgoing_packets
            ):
                return

        self._send_query_to_nameserver(
            state,
            target,
            self._root_nameserver["ip"],
            self._root_nameserver["port"],
            outgoing_packets
        )

    def generate_packets(self):
        outgoing_packets = []

        # First send responses to clients that were served from cache.
        for pending in self._pending_responses:
            if isinstance(pending, dict):
                outgoing_packets.append(pending["cached_response"])

        self._pending_responses = []

        # Process upstream responses before checking timeouts.
        for response in self._upstream_responses:
            query_key = self._get_query_key(response)
            outstanding = self._outstanding_queries.pop(query_key, None)

            if outstanding is None:
                continue

            state = outstanding["state"]
            payload = response.get_payload()
            answer = payload.get_answer()
            authority = payload.get_authority()
            additional = payload.get_additional()

            # Cache and process referral information.
            if authority:
                self._cache_referral(
                    authority,
                    additional,
                    state["current_name"]
                )

                valid_ns, valid_glue = self._get_referral_records(response)

                if valid_ns:
                    self._update_best_referral(
                        state,
                        valid_ns,
                        valid_glue
                    )

                    state["fallback_nameservers"] = [
                        {"ip": glue.get_rr_data(), "port": 53}
                        for glue in valid_glue
                    ]

            # Identify answer record types.
            cname_records = [
                record for record in answer
                if record.get_record_type() == "CNAME"
            ]

            a_records = [
                record for record in answer
                if record.get_record_type() == "A"
            ]

            # Reject ambiguous CNAME targets before caching the answer.
            if cname_records:
                targets = {
                    self._normalize_name(record.get_rr_data())
                    for record in cname_records
                }

                if len(targets) != 1:
                    self._finish_resolution(
                        state, outgoing_packets, DnsStatusCodes.SERVFAIL.value
                    )
                    continue

            # Record TTLs when the response reaches the resolver.
            state["answer_entries"].extend(
                self._make_expiring_entries(answer)
            )

            # An A record completes the resolution.
            if a_records:
                self._finish_resolution(state, outgoing_packets)
                continue

            # Follow a valid CNAME chain.
            if cname_records:
                self._follow_cname(
                    state,
                    cname_records,
                    outgoing_packets
                )
                continue

            # Try the next nameserver from the referral.
            referral_ns, referral_glue = self._get_referral_records(
                response
            )

            if referral_ns:
                state["fallback_nameservers"] = [
                    {"ip": glue.get_rr_data(), "port": 53}
                    for glue in referral_glue
                ]

            if not self._send_next_nameserver(
                state,
                state["current_name"],
                outgoing_packets
            ):
                self._finish_resolution(state, outgoing_packets)

        self._upstream_responses = []

        # Process timeouts after responses for this tick.
        # This allows a response arriving on the timeout boundary
        # to be accepted.
        timed_out = [
            (key, value)
            for key, value in self._outstanding_queries.items()
            if self._current_time - value["sent_at"]
            >= self._nameserver_timeout
        ]

        for query_key, outstanding in timed_out:
            self._outstanding_queries.pop(query_key, None)
            state = outstanding["state"]

            if not self._send_next_nameserver(
                state,
                state["current_name"],
                outgoing_packets
            ):
                self._finish_resolution(state, outgoing_packets)

        # Start newly received client queries.
        for client_query in self._pending_client_queries:
            self._start_resolution(
                client_query,
                outgoing_packets
            )

        self._pending_client_queries = []

        return outgoing_packets

    def process_packet(self, packet):
        payload = packet.get_payload()
        header = payload.get_header()
        if header is None:
            return
        if header.get_dns_type() == DnsTypes.QUERY.value:
            question = payload.get_question()
            key = self._get_cache_key(
                question.get_dns_name(), question.get_question_type()
            )
            cached = self._get_cached_response(key)
            if cached is not None:
                answer, authority, additional = cached
                self._pending_responses.append({
                    "cached_response": self._create_client_response(
                        packet, answer, authority, additional
                    )
                })
            else:
                self._pending_client_queries.append(packet)
        elif header.get_dns_type() == DnsTypes.RESPONSE.value:
            self._upstream_responses = getattr(self, "_upstream_responses", [])
            self._upstream_responses.append(packet)