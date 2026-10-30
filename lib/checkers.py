import json
from abc import ABC, abstractmethod
from collections import Counter
from decimal import Decimal
from itertools import combinations
from config_schema import CONFIG_SCHEMA, APPLICATION_SCHEMAS_BY_TYPE, EVENT_SCHEMAS_BY_TYPE, ConfigValidator
from packet import DnsTypes
from utils import ContentServerStatus, Formatter

class SimulationChecker(ABC):
    verbose = False

    def set_verbose(self, value):
        self.verbose = value

    def _print_if_verbose(self,string=""):
        if self.verbose:
            print(string)

    @abstractmethod
    def check(self, time):
        pass

    @abstractmethod
    def print_report(self):
        pass

class ForwardingChecker(SimulationChecker):
    def __init__(self, network):
        self.network = network

    def check(self, time):
        pass

    def print_report(self):
        print("Data-plane traffic stats for {}: fwd {} drop {}".format(
            self.network.get_id(), self.network.get_forwarded_traffic_packets(), self.network.get_dropped_traffic_packets()))

class DnsChecker(SimulationChecker):
    def __init__(self, network, endhosts_list, lns_ips=(), ns_ips=(), client_ips=(),
                 configured_records_by_ns=None, configured_record_ttls_by_ns=None,
                 lns_ip_ports=(), ns_ip_ports=()):
        self.network = network
        self.client_ips = set(client_ips)
        self.ip2host = {}
        for eh in endhosts_list:
            self.ip2host[eh.get_ip()] = eh.get_id()
        self.time2dnspackets = {}

    def check(self, time):
        dns_packets = self.network.get_current_dns_packets()
        self.time2dnspackets[time] = dns_packets
        if len(dns_packets) > 0:
            self._print_if_verbose("[DNS CHECK] at time {}: {} DNS packet(s):".format(time, len(dns_packets)))
            for p in dns_packets:
                self._print_if_verbose("  * {} with payload {}".format(p, p.get_payload()))
            self._print_if_verbose()

    def print_report(self):
        chronological = []
        for t in sorted(self.time2dnspackets):
            for p in self.time2dnspackets[t]:
                chronological.append((t, p))
        print("Total number of DNS packets crossing the network: {}".format(len(chronological)))

        queries_sent, replies_received, replies_with_ip = self._get_client_query_reply_stats(chronological)
        print("Total number of DNS queries sent by clients: {}".format(queries_sent))
        print("Total number of DNS replies received by clients: {}".format(replies_received))
        print("Total number of DNS replies including an IP for the queried name: {}".format(replies_with_ip))

        if chronological:
            traces = sorted(self._split_into_traces(chronological), key=lambda trace: trace["packets"][0][0])
            for query_num, trace in enumerate(traces, start=1):
                dns_name = trace["packets"][0][1].get_payload().get_question().get_dns_name()
                report = "= DNS query {} =\n\n".format(query_num) + self._get_report_for_name(dns_name, trace)
                print("\n{}".format(report.strip()))

    def _get_client_query_reply_stats(self, chronological):
        queries_sent = 0
        replies_received = 0
        replies_with_ip = 0
        for _t, p in chronological:
            header = p.get_payload().get_header()
            if header.get_dns_type() == DnsTypes.QUERY.value and p.get_source() in self.client_ips:
                queries_sent += 1
            elif header.get_dns_type() == DnsTypes.RESPONSE.value and p.get_destination() in self.client_ips:
                replies_received += 1
                if any(r.get_record_type() == "A" for r in p.get_payload().get_answer()):
                    replies_with_ip += 1
        return queries_sent, replies_received, replies_with_ip

    def _split_into_traces(self, packets):
        traces_by_rid = {}
        order = []   # resolution IDs in the order first seen, so traces come out chronological
        for (t, p) in packets:
            header = p.get_payload().get_header()
            rid = header.get_resolution_id()
            if rid not in traces_by_rid:
                traces_by_rid[rid] = {"client": p.get_source(), "packets": [], "final_reply": None}
                order.append(rid)
            trace = traces_by_rid[rid]
            trace["packets"].append((t, p))
            if (trace["final_reply"] is None and header.get_dns_type() == DnsTypes.RESPONSE.value
                    and p.get_destination() == trace["client"]):
                trace["final_reply"] = (t, p)  # the original querier has its answer - nothing further is owed
        return [traces_by_rid[rid] for rid in order]

    def _get_report_for_name(self, dns_name, trace):
        packets = trace["packets"]
        start_time, first_packet = packets[0]
        origin_host = self._get_hostname(first_packet.get_source())
        lines = ["DNS trace to resolve {} for {} at time {}".format(dns_name, origin_host, start_time)]
        for i, (t, p) in enumerate(packets, start=1):
            header = p.get_payload().get_header()
            src_host = self._get_hostname(p.get_source())
            dst_host = self._get_hostname(p.get_destination())
            if header.get_dns_type() == DnsTypes.QUERY.value:
                question = p.get_payload().get_question()
                lines.append(" {} {} -> {}: query for name {} (QID {}, RID {})".format(i, src_host, dst_host, question.get_dns_name(), header.get_query_id(), header.get_resolution_id()))
            else:
                lines.append(" {} {} -> {}: reply (QID {}, RID {})".format(i, src_host, dst_host, header.get_query_id(), header.get_resolution_id()))
        report = "\n".join(lines) + "\n\n"
        final_reply = trace["final_reply"]
        if final_reply is None:
            candidate_time, candidate_packet = packets[-1]
            if candidate_packet.get_payload().get_header().get_dns_type() == DnsTypes.RESPONSE.value and candidate_packet.get_destination() == first_packet.get_source():
                final_reply = (candidate_time, candidate_packet)
        if final_reply is not None:
            last_time, last_packet = final_reply
            intro_line = "Final DNS reply received by client (ip {}, port {}) for name {}".format(
                first_packet.get_source(), first_packet.get_source_port(), dns_name)
            report += Formatter.get_dig_output(last_packet, intro_line=intro_line)
        else:
            last_time, last_packet = packets[-1]
            report += "No DNS reply received by client (ip {}, port {}) for name {} before the end of the simulation".format(
                first_packet.get_source(), first_packet.get_source_port(), dns_name)
        return report

    def _get_hostname(self, ip):
        return self.ip2host.get(ip, ip)

class RevenueChecker(SimulationChecker):
    @staticmethod
    def _collapse_revenue_steps(steps):
        ranges_by_key = {}   # dict: (description, revenue) -> list of [start_time, end_time] ranges, in the order each was started
        key_order = []       # keys in the order first seen, used as this key's tie-break below
        for time, revenue, description in steps:
            key = (description, revenue)
            if key not in ranges_by_key:
                ranges_by_key[key] = []
                key_order.append(key)
            ranges = ranges_by_key[key]
            if ranges and ranges[-1][1] == time - 1:
                ranges[-1][1] = time
            else:
                ranges.append([time, time])

        key_rank = {key: rank for rank, key in enumerate(key_order)}
        runs = [
            (start, end, revenue, description)
            for (description, revenue), ranges in ranges_by_key.items()
            for (start, end) in ranges
        ]
        runs.sort(key=lambda run: (run[0], key_rank[(run[3], run[2])]))
        return runs

class ContentClientRevenueChecker(RevenueChecker):
    def __init__(self, network, links_list, endhosts_list, content_server_monitors, content_clients=(), configured_dns_records=None):
        self.network = network
        self.ip2host = {eh.get_ip(): eh.get_id() for eh in endhosts_list}
        self.host_ip2delay = self._build_host_delays(links_list)
        self.host_ip2link = self._build_host_links(links_list)
        self.average_path_delay = self._get_average_path_delay()
        self.contentserver_ip2host_ip = {
            server_ip: monitor.get_host_ip()
            for monitor in content_server_monitors
            for server_ip in monitor.get_content_servers()
        }
        self.contentserver_ip2monitor = {
            server_ip: monitor
            for monitor in content_server_monitors
            for server_ip in monitor.get_content_servers()
        }
        self.content_clients = dict(content_clients)   # dict: client_app_id (i.e. (client_ip, port)) -> that client's ContentClient application
        self.client_app_ids = set(self.content_clients.keys())

        self.configured_dns_records = {
            name: ({ips} if isinstance(ips, str) else set(ips))
            for name, ips in (configured_dns_records or {}).items()
        }

        self.server_ips = {}        # dict: query_key -> set of content server IPs ever resolved to
        self.path_delays = {}       # dict: (client_ip, server_ip) -> network path delay to that content server (query- and port-independent: a purely topological host-to-host property, the same for every application on a given host)
        self.revenues = {}          # dict: query_key -> total revenue accrued so far, summed over every resolved IP
        self.working_steps = {}     # dict: (query_key, server_ip) -> steps that IP spent working, at load <= HIGH_LOAD_THRESHOLD
        self.nonworking_steps = {}  # dict: (query_key, server_ip) -> steps that IP spent failed, at load <= HIGH_LOAD_THRESHOLD
        self.high_load_steps = {}   # dict: (query_key, server_ip) -> steps that IP spent over HIGH_LOAD_THRESHOLD
        self.pending_steps = {}     # dict: query_key -> steps spent with no resolved path at all

        self.step_log = {}    # dict: query_key -> list of (time, revenue, description) in chronological order
        self.resolved_queries = set()  # set of query_key that have delivered at least one resolved (working/nonworking/high-load) step - see check(): once a query has resolved, it's the client's own responsibility to send a fresh query once its answer goes stale, so no further PENDING_PATH_PENALTY accrues for it
        self._never_answered_penalty_applied = False  # guards _apply_never_answered_penalty() against re-applying itself if print_report() is ever called more than once

    def _build_host_delays(self, links_list):
        network_id = self.network.get_id()
        host_ip2delay = {}
        for link in links_list:
            for side in (0, 1):
                if link.get_node(side) != network_id:
                    host_ip2delay[link.get_interface_ip(side)] = link.get_properties().get("delay", 0)
        return host_ip2delay

    def _build_host_links(self, links_list):
        network_id = self.network.get_id()
        host_ip2link = {}
        for link in links_list:
            for side in (0, 1):
                if link.get_node(side) != network_id:
                    host_ip2link[link.get_interface_ip(side)] = link
        return host_ip2link

    def _get_average_path_delay(self):
        host_pairs = list(combinations(self.host_ip2delay.keys(), 2))
        if not host_pairs:
            return 0
        return sum(self.host_ip2delay[a] + self.host_ip2delay[b] for a, b in host_pairs) / len(host_pairs)

    NONWORKING_REVENUE = -100

    INVALID_SERVER_PENALTY = -100

    INVALID_IP_MAPPING_PENALTY = -100

    PENDING_PATH_PENALTY = -5

    NEVER_ANSWERED_PENALTY = -200

    HIGH_LOAD_PENALTY = -25
    HIGH_LOAD_THRESHOLD = 1

    def check(self, time):
        for client_app_id, content_client in self.content_clients.items():
            client_ip, _client_port = client_app_id
            for dns_name in content_client.get_queried_names():
                for query_id in content_client.get_pending_query_ids(dns_name, time):
                    query_key = (client_app_id, dns_name, query_id)
                    if query_key in self.resolved_queries:
                        continue
                    self.revenues[query_key] = self.revenues.get(query_key, Decimal("0")) + self.PENDING_PATH_PENALTY
                    self.pending_steps[query_key] = self.pending_steps.get(query_key, 0) + 1
                    self._log_step(query_key, time, self.PENDING_PATH_PENALTY, "no path because name is not resolved yet")

                by_query = content_client.get_cached_ips_by_session(dns_name, time)
                merged_loads = {}
                contributors = {}
                record_names = {}   # server_ip -> {query_id: recordName} - see ContentClient.get_cached_ips_by_session/_cache_answer
                for query_id, ip_info in by_query.items():
                    for server_ip, info in ip_info.items():
                        merged_loads[server_ip] = merged_loads.get(server_ip, 0) + info["load"]
                        contributors.setdefault(server_ip, {})[query_id] = info["load"]
                        record_names.setdefault(server_ip, {})[query_id] = info["recordName"]

                expected_ips = self.configured_dns_records.get(dns_name)
                for server_ip, total_load in merged_loads.items():
                    ip_contributors = contributors[server_ip]
                    for query_id, own_load in ip_contributors.items():
                        query_key = (client_app_id, dns_name, query_id)
                        other_contributors = {qid: share for qid, share in ip_contributors.items() if qid != query_id}

                        matches_expected = bool(expected_ips) and server_ip in expected_ips
                        if not matches_expected:
                            record_name = record_names[server_ip][query_id]
                            if record_name != dns_name:
                                alias_expected_ips = self.configured_dns_records.get(record_name)
                                matches_expected = bool(alias_expected_ips) and server_ip in alias_expected_ips

                        if not matches_expected:
                            self.resolved_queries.add(query_key)
                            step_revenue = self.INVALID_IP_MAPPING_PENALTY
                            self.revenues[query_key] = self.revenues.get(query_key, Decimal("0")) + step_revenue
                            load_clause = self._format_load_clause(own_load, other_contributors)
                            if not expected_ips:
                                description = "{} via {} which isn't a configured DNS record at all".format(load_clause, server_ip)
                            else:
                                description = "{} via {} but the configured DNS records map {} to {}".format(
                                    load_clause, server_ip, dns_name, self._format_ip_set(expected_ips))
                            self._log_step(query_key, time, step_revenue, description)
                            continue
                        if server_ip not in self.contentserver_ip2host_ip:
                            self.resolved_queries.add(query_key)
                            step_revenue = self.INVALID_SERVER_PENALTY
                            self.revenues[query_key] = self.revenues.get(query_key, Decimal("0")) + step_revenue
                            description = "{} via {} which is not a content server".format(
                                self._format_load_clause(own_load, other_contributors), server_ip)
                            self._log_step(query_key, time, step_revenue, description)
                            continue
                        self.resolved_queries.add(query_key)
                        self.server_ips.setdefault(query_key, set()).add(server_ip)

                        delay_key = (client_ip, server_ip)
                        if delay_key not in self.path_delays:
                            self.path_delays[delay_key] = self._get_path_delay(client_ip, server_ip)
                        delay = self.path_delays[delay_key]

                        step_key = (query_key, server_ip)
                        load_clause = self._format_load_clause(own_load, other_contributors)
                        if total_load > self.HIGH_LOAD_THRESHOLD:
                            step_revenue = self.HIGH_LOAD_PENALTY
                            self.high_load_steps[step_key] = self.high_load_steps.get(step_key, 0) + 1
                            description = "{} via {} with over {} unit(s) of load".format(load_clause, server_ip, self.HIGH_LOAD_THRESHOLD)
                        else:
                            path_down = self._is_path_down(client_ip, server_ip)
                            monitor = self.contentserver_ip2monitor.get(server_ip)
                            server_failed = not path_down and monitor is not None and monitor.get_status(server_ip) != ContentServerStatus.WORKING.value
                            if path_down or server_failed:
                                step_revenue = self.NONWORKING_REVENUE
                                self.nonworking_steps[step_key] = self.nonworking_steps.get(step_key, 0) + 1
                                if path_down:
                                    description = "{} via {} with a down link along the path to it".format(load_clause, server_ip)
                                else:
                                    description = "{} via {} with a failed content server".format(load_clause, server_ip)
                            else:
                                step_revenue = self._get_revenue(delay)
                                self.working_steps[step_key] = self.working_steps.get(step_key, 0) + 1
                                description = "{} via {} with delay {} vs average delay {:.2f}".format(load_clause, server_ip, delay, self.average_path_delay)
                        self.revenues[query_key] = self.revenues.get(query_key, Decimal("0")) + step_revenue
                        self._log_step(query_key, time, step_revenue, description)

    def _get_path_delay(self, client_ip, server_ip):
        server_host_ip = self.contentserver_ip2host_ip[server_ip]
        return self.host_ip2delay.get(client_ip, 0) + self.host_ip2delay.get(server_host_ip, 0)

    def _is_path_down(self, client_ip, server_ip):
        server_host_ip = self.contentserver_ip2host_ip[server_ip]
        client_link = self.host_ip2link.get(client_ip)
        server_link = self.host_ip2link.get(server_host_ip)
        return (client_link is not None and not client_link.is_up()) or \
            (server_link is not None and not server_link.is_up())

    def _format_load_clause(self, load, other_contributors):
        clause = "{} unit{} of load".format(load, "" if load == 1 else "s")
        if other_contributors:
            extra = ", ".join(
                "{} from query {}".format(share, query_id)
                for query_id, share in sorted(other_contributors.items()))
            clause += " (plus {})".format(extra)
        return clause

    def _format_ip_set(self, ips):
        sorted_ips = sorted(ips)
        if len(sorted_ips) == 1:
            return sorted_ips[0]
        return "one of {}".format(", ".join(sorted_ips))

    def _log_step(self, query_key, time, revenue, description):
        self.step_log.setdefault(query_key, []).append((time, revenue, description))

    def _get_hostname(self, ip):
        return self.ip2host.get(ip, ip)

    def _format_client_app_id(self, client_app_id):
        client_ip, port = client_app_id
        return "{}:{}".format(self._get_hostname(client_ip), port)

    REVENUE_SCALE = 100

    def _get_revenue(self, delay):
        if self.average_path_delay == 0:
            return Decimal(self.REVENUE_SCALE if delay == 0 else -self.REVENUE_SCALE)
        return Decimal(str(round(self.REVENUE_SCALE * (self.average_path_delay - delay) / self.average_path_delay, 2)))

    def _get_event_key(self, query_key):
        client_app_id, _dns_name, query_id = query_key
        return (client_app_id, self.content_clients[client_app_id].get_session_id(query_id))

    def _apply_never_answered_penalty(self):
        if self._never_answered_penalty_applied:
            return
        self._never_answered_penalty_applied = True

        resolved_events = {self._get_event_key(query_key) for query_key in self.resolved_queries}

        delta_per_step = self.NEVER_ANSWERED_PENALTY - self.PENDING_PATH_PENALTY
        for query_key, steps in self.pending_steps.items():
            if not steps or query_key in self.resolved_queries or self._get_event_key(query_key) in resolved_events:
                continue
            self.revenues[query_key] = self.revenues.get(query_key, Decimal("0")) + steps * delta_per_step
            self.step_log[query_key] = [
                (time, self.NEVER_ANSWERED_PENALTY, "name never resolved") if revenue == self.PENDING_PATH_PENALTY
                else (time, revenue, description)
                for (time, revenue, description) in self.step_log.get(query_key, [])
            ]

    def print_report(self):
        print("\n** Revenue Report **\n")
        self._apply_never_answered_penalty()
        print("Total revenues: {:.2f}".format(sum(self.revenues.values())))

        any_query_ever_sent = bool(self.revenues) or any(
            content_client.get_queried_names() for content_client in self.content_clients.values())
        if not any_query_ever_sent:
            return

        query_keys = set(self.revenues.keys())   # (client_app_id, dns_name, queryId)
        if not query_keys:
            print("No DNS reply resolved a name to a content server.")
            return

        events = {}   # dict: (client_app_id, session_id) -> list of (query_id, dns_name, steps), in query_id order
        for (client_app_id, dns_name, query_id) in sorted(query_keys, key=lambda k: (k[0], k[2])):
            steps = self.step_log.get((client_app_id, dns_name, query_id), ())
            session_id = self.content_clients[client_app_id].get_session_id(query_id)
            events.setdefault((client_app_id, session_id), []).append((query_id, dns_name, steps))

        for event_number, (client_app_id, session_id) in enumerate(sorted(events), start=1):
            group = events[(client_app_id, session_id)]
            _, event_dns_name, first_steps = group[0]
            event_time = first_steps[0][0]
            client_app_id = self._format_client_app_id(client_app_id)
            print("+ event {} is {} accesscontent for {} at time {}".format(
                event_number, client_app_id, event_dns_name, event_time))
            for (query_id, dns_name, steps) in group:
                query_revenue = sum(revenue for _, revenue, _ in steps)
                print("  - query {} from {} to {}: total revenue {:.2f}".format(
                    query_id, client_app_id, dns_name, query_revenue))
                for (start_time, end_time, revenue, description) in self._collapse_steps(steps):
                    if start_time == end_time:
                        print("    > step {}: {} --> revenue {:.2f}".format(start_time, description, revenue))
                    else:
                        print("    > steps {}-{}: {} --> revenue {:.2f} each step".format(
                            start_time, end_time, description, revenue))

    def _collapse_steps(self, steps):
        return self._collapse_revenue_steps(steps)

class DnsClientRevenueChecker(RevenueChecker):
    def __init__(self, network, endhosts_list, dns_client_ips=()):
        self.network = network
        self.ip2host = {eh.get_ip(): eh.get_id() for eh in endhosts_list}
        self.dns_client_ips = set(dns_client_ips)

        self.queries = {}
        self.resolved = set()   # set of resolutionId that have received a matching reply
        self.revenues = {}      # dict: resolutionId -> total revenue accrued so far
        self.step_log = {}      # dict: resolutionId -> list of (time, revenue, description), chronological
        self._never_answered_penalty_applied = False   # guards _apply_never_answered_penalty() against re-applying itself if print_report() is ever called more than once

        self.total_dns_packets = 0

    ANSWERED_REVENUE = 200

    ANSWERED_NO_IP_REVENUE = 20

    PENDING_PATH_PENALTY = -5

    NEVER_ANSWERED_PENALTY = -200

    DNS_PACKET_PENALTY = -5

    def check(self, time):
        self._process_step(time, self.network.get_current_dns_packets())

    def _process_step(self, time, dns_packets):

        self.total_dns_packets += len(dns_packets)

        for p in dns_packets:
            header = p.get_payload().get_header()
            if header.get_dns_type() == DnsTypes.QUERY.value and p.get_source() in self.dns_client_ips:
                rid = header.get_resolution_id()
                dns_name = p.get_payload().get_question().get_dns_name()
                self.queries[rid] = (dns_name, p.get_source(), time)

        for p in dns_packets:
            header = p.get_payload().get_header()
            if header.get_dns_type() == DnsTypes.RESPONSE.value and p.get_destination() in self.dns_client_ips:
                rid = header.get_resolution_id()
                if rid in self.queries and rid not in self.resolved:
                    self.resolved.add(rid)
                    dns_name, _client_ip, _send_time = self.queries[rid]
                    has_ip = any(r.get_record_type() == "A" for r in p.get_payload().get_answer())
                    revenue = self.ANSWERED_REVENUE if has_ip else self.ANSWERED_NO_IP_REVENUE
                    description = "query for {} was answered with {}".format(
                        dns_name, "an IP address" if has_ip else "no IP address")
                    self.revenues[rid] = self.revenues.get(rid, 0) + revenue
                    self._log_step(rid, time, revenue, description)

        for rid, (dns_name, _client_ip, _send_time) in self.queries.items():
            if rid in self.resolved:
                continue
            self.revenues[rid] = self.revenues.get(rid, 0) + self.PENDING_PATH_PENALTY
            self._log_step(rid, time, self.PENDING_PATH_PENALTY, "query for {} not yet answered".format(dns_name))

    def _log_step(self, rid, time, revenue, description):
        self.step_log.setdefault(rid, []).append((time, revenue, description))

    def _get_hostname(self, ip):
        return self.ip2host.get(ip, ip)

    def _apply_never_answered_penalty(self):
        if self._never_answered_penalty_applied:
            return
        self._never_answered_penalty_applied = True

        delta = self.NEVER_ANSWERED_PENALTY - self.PENDING_PATH_PENALTY
        for rid in self.queries:
            if rid in self.resolved:
                continue
            steps = self.step_log.get(rid, ())
            pending_steps = sum(1 for (_, revenue, _) in steps if revenue == self.PENDING_PATH_PENALTY)
            if not pending_steps:
                continue
            self.revenues[rid] = self.revenues.get(rid, 0) + pending_steps * delta
            self.step_log[rid] = [
                (t, self.NEVER_ANSWERED_PENALTY, "query never answered") if revenue == self.PENDING_PATH_PENALTY
                else (t, revenue, description)
                for (t, revenue, description) in steps
            ]

    def print_report(self):
        print("\n** Revenue Report **\n")
        self._apply_never_answered_penalty()
        packet_penalty = self.total_dns_packets * self.DNS_PACKET_PENALTY
        print("Total revenues: {:.2f}".format(sum(self.revenues.values()) + packet_penalty))

        if self.queries:
            print("+ events")
            for i, rid in enumerate(sorted(self.queries, key=lambda r: self.queries[r][2]), start=1):
                dns_name, client_ip, send_time = self.queries[rid]
                steps = self.step_log.get(rid, [])
                query_revenue = sum(revenue for (_, revenue, _) in steps)
                outcome = "answered" if rid in self.resolved else "never answered"
                print("  - query {} from {} for {} at time {} ({}): total revenue {:.2f}".format(
                    i, self._get_hostname(client_ip), dns_name, send_time, outcome, query_revenue))
                for (start_time, end_time, revenue, description) in self._collapse_steps(steps):
                    if start_time == end_time:
                        print("    > time {}: {} --> revenue {:.2f}".format(start_time, description, revenue))
                    else:
                        print("    > times {}-{}: {} --> revenue {:.2f} each step".format(
                            start_time, end_time, description, revenue))

        print("+ DNS packets")
        print("  - total number of DNS packets: {} --> revenue {:.2f}".format(
            self.total_dns_packets, packet_penalty))

    def _collapse_steps(self, steps):
        return self._collapse_revenue_steps(steps)

class ConfigOptimizationChecker(SimulationChecker):
    def __init__(self, original_config_file, optimized_config_file):
        self.original_config_file = original_config_file
        self.optimized_config_file = optimized_config_file
        with open(original_config_file, 'rt') as f:
            self.original_config = json.load(f)
        with open(optimized_config_file, 'rt') as f:
            self.optimized_config = json.load(f)
        self.violations = (
            self._diff(self.original_config, self.optimized_config, "")
            + self._get_duplicate_content_server_assignments(self.optimized_config)
            + self._get_duplicate_port_assignments(self.optimized_config)
            + self._get_authoritative_name_server_host_conflicts(self.optimized_config)
            + self._get_schema_violations(self.optimized_config)
        )

    def check(self, time):
        pass

    def has_errors(self):
        return bool(self.violations)

    @staticmethod
    def _is_local_name_server_entry(obj):
        return isinstance(obj, dict) and obj.get("type") == "LocalNameServer"

    def _diff(self, original, optimized, path):
        if self._is_local_name_server_entry(original) and self._is_local_name_server_entry(optimized):
            return self._diff_dict(original, optimized, path, skip_keys={"parameters"})
        if isinstance(original, dict) and isinstance(optimized, dict):
            return self._diff_dict(original, optimized, path, skip_keys=set())
        if isinstance(original, list) and isinstance(optimized, list):
            if path == "applications":
                return self._diff_applications(original, optimized, path)
            return self._diff_list(original, optimized, path)
        if original != optimized:
            return ["{}: changed from {!r} to {!r}".format(path or "<root>", original, optimized)]
        return []

    def _diff_applications(self, original, optimized, path):
        violations = self._diff_list(original, optimized[:len(original)], path)
        for i, app in enumerate(optimized[len(original):], start=len(original)):
            if not (isinstance(app, dict) and app.get("type") == "AuthoritativeNameServer"):
                violations.append(
                    "{}[{}]: application added by the optimizer is not an AuthoritativeNameServer "
                    "- only new AuthoritativeNameServer applications may be added".format(path, i))
        return violations

    def _get_duplicate_content_server_assignments(self, config):
        names_by_ip = {}
        for app in config.get("applications", []):
            if app.get("type") != "AuthoritativeNameServer":
                continue
            records_a = app.get("parameters", {}).get("records A", {})
            for dns_name, records in records_a.items():
                for record in records:
                    ip = record.get("ip")
                    names_by_ip.setdefault(ip, set()).add(dns_name)

        violations = []
        for ip, names in sorted(names_by_ip.items()):
            if len(names) > 1:
                violations.append(
                    "records A: content server {} is used to answer more than one name ({}) - "
                    "every name must resolve to a distinct content server IP".format(ip, ", ".join(sorted(names))))
        return violations

    def _get_duplicate_port_assignments(self, config):
        indices_by_host_port = {}
        for i, app in enumerate(config.get("applications", [])):
            if not isinstance(app, dict):
                continue
            key = (app.get("eId"), app.get("port"))
            indices_by_host_port.setdefault(key, []).append(i)

        violations = []
        for (eId, port), indices in sorted(indices_by_host_port.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
            if len(indices) > 1:
                entries = ", ".join("applications[{}]".format(i) for i in indices)
                violations.append(
                    "{}: {} applications all assign host {} port {} - two applications on the "
                    "same host can never share a port".format(entries, len(indices), eId, port))
        return violations

    def _get_authoritative_name_server_host_conflicts(self, config):
        ns_indices_by_host = {}
        other_indices_by_host = {}
        for i, app in enumerate(config.get("applications", [])):
            if not isinstance(app, dict):
                continue
            eId = app.get("eId")
            app_type = app.get("type")
            if app_type == "AuthoritativeNameServer":
                ns_indices_by_host.setdefault(eId, []).append(i)
            elif app_type in ("LocalNameServer", "ContentClient"):
                other_indices_by_host.setdefault(eId, []).append(i)

        violations = []
        conflicting_hosts = set(ns_indices_by_host) & set(other_indices_by_host)
        for eId in sorted(conflicting_hosts, key=str):
            other_indices = other_indices_by_host[eId]
            entries = ", ".join("applications[{}]".format(i) for i in sorted(ns_indices_by_host[eId] + other_indices))
            other_types = sorted({config["applications"][i].get("type") for i in other_indices})
            violations.append(
                "{}: host {} runs an AuthoritativeNameServer alongside a {} - an "
                "AuthoritativeNameServer must never share a host with a LocalNameServer or "
                "ContentClient".format(entries, eId, " and a ".join(other_types)))
        return violations

    def _get_schema_violations(self, config):
        violator = ConfigValidator(CONFIG_SCHEMA)
        violations = [
            "{}: {}".format(self._format_schema_path(list(error.absolute_path)), error.message)
            for error in violator.iter_errors(config)
        ]

        for i, app in enumerate(config.get("applications", [])):
            violations.extend(self._get_schema_violations_for_one(
                app, "applications[{}]".format(i), APPLICATION_SCHEMAS_BY_TYPE, "application"))
        for i, event in enumerate(config.get("events", [])):
            violations.extend(self._get_schema_violations_for_one(
                event, "events[{}]".format(i), EVENT_SCHEMAS_BY_TYPE, "event"))
        return violations

    def _get_schema_violations_for_one(self, entry, path, schemas_by_type, noun):
        entry_type = entry.get("type") if isinstance(entry, dict) else None
        schema = schemas_by_type.get(entry_type)
        if schema is None:
            article = "an" if noun[0] in "aeiou" else "a"
            return ["{}.type: '{}' is not {} {} type the config parser supports (one of {})".format(
                path, entry_type, article, noun, sorted(schemas_by_type.keys()))]
        return [
            "{}: {}".format(self._format_schema_path([path] + list(error.absolute_path)), error.message)
            for error in ConfigValidator(schema).iter_errors(entry)
        ]

    @staticmethod
    def _format_schema_path(path):
        result = ""
        for p in path:
            if isinstance(p, int):
                result += "[{}]".format(p)
            elif result:
                result += ".{}".format(p)
            else:
                result = str(p)
        return result or "<root>"

    def _diff_dict(self, original, optimized, path, skip_keys):
        violations = []
        for key in sorted(set(original.keys()) | set(optimized.keys()), key=str):
            if key in skip_keys:
                continue
            sub_path = "{}.{}".format(path, key) if path else str(key)
            if key not in optimized:
                violations.append("{}: present in the original configuration but missing from the optimized one".format(sub_path))
            elif key not in original:
                violations.append("{}: present in the optimized configuration but not in the original".format(sub_path))
            else:
                violations.extend(self._diff(original[key], optimized[key], sub_path))
        return violations

    def _diff_list(self, original, optimized, path):
        if len(original) != len(optimized):
            return ["{}: list has {} entries in the original configuration but {} in the optimized one".format(
                path or "<root>", len(original), len(optimized))]
        violations = []
        for i, (o_item, opt_item) in enumerate(zip(original, optimized)):
            violations.extend(self._diff(o_item, opt_item, "{}[{}]".format(path, i)))
        return violations

    def print_report(self):
        if not self.violations:
            print("Config optimization check: OK")
            return
        print("Config optimization check: FAILED - {} unauthorized change(s) found outside "
              "LocalNameServer application \"parameters\":".format(len(self.violations)))
        for violation in self.violations:
            print("* {}".format(violation))

