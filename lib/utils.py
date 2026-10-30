import random
from collections import deque
from enum import Enum

from packet import DnsTypes

class ContentServerStatus(Enum):
    WORKING = "working"  # serving content normally
    FAILED = "failed"    # unreachable or not serving content at all

class ContentServerMonitor:
    LOOKAHEAD_STEPS = 10   # how many future steps of status are precomputed at once

    def __init__(self, host, content_servers, failure_probability=0.01, recovery_probability=0.05, seed=None):
        self._host = host  # the EndHost this monitor watches over - it has no reference back to this monitor, only a receive_content_server_status_update() method that this monitor calls whenever it recomputes a server's future schedule
        self._host_id = host.get_id()
        self._host_ip = host.get_ip()
        self._content_servers = content_servers
        self._status = {ip: ContentServerStatus.WORKING.value for ip in content_servers}
        self._failure_probability = failure_probability
        self._recovery_probability = recovery_probability
        self._rng = random.Random(seed)
        self._scheduled_statuses = {ip: deque() for ip in content_servers}  # precomputed future statuses, one entry per upcoming step, oldest first
        self._random_failures_active = False  # no server transitions to "failed" until activate_random_failures() is called
        print("Created content server monitor for end-host {} ({})".format(self._host_id, ", ".join(content_servers)))

    def activate_random_failures(self):
        self._random_failures_active = True

    def is_random_failures_active(self):
        return self._random_failures_active

    def get_host_id(self):
        return self._host_id

    def get_host_ip(self):
        return self._host_ip

    def get_content_servers(self):
        return self._content_servers

    def get_status(self, ip):
        if ip not in self._status:
            raise Exception("ERROR: {} is not a content server tracked by this monitor".format(ip))
        return self._status[ip]

    def set_status(self, ip, status):
        if ip not in self._status:
            raise Exception("ERROR: {} is not a content server tracked by this monitor".format(ip))
        if status not in {m.value for m in ContentServerStatus}:
            raise Exception("ERROR: cannot set the status of a content server to {}, must be one of {}".format(
                status, [m.value for m in ContentServerStatus]))
        self._status[ip] = status

    def _schedule_future_statuses(self, ip):
        schedule = self._scheduled_statuses[ip]
        if schedule:
            return
        status = self._status[ip]
        for _ in range(self.LOOKAHEAD_STEPS):
            if self._random_failures_active:
                if status == ContentServerStatus.FAILED.value:
                    recovery_outcome = self._rng.random()
                    if recovery_outcome < self._recovery_probability:
                        status = ContentServerStatus.WORKING.value
                elif status == ContentServerStatus.WORKING.value:
                    if self._rng.random() < self._failure_probability:
                        status = ContentServerStatus.FAILED.value
            schedule.append(status)
        self._host.receive_content_server_status_update(ip, schedule)

    def update_statuses(self):
        for ip in self._content_servers:
            self._schedule_future_statuses(ip)
            self._status[ip] = self._scheduled_statuses[ip].popleft()

class Formatter:
    @staticmethod
    def _get_next_tab_stop(column, tab_size=8):
        return ((column // tab_size) + 1) * tab_size

    @staticmethod
    def _get_question_fields(question):
        return [f";{question.dnsName}", "", "IN", question.questionType, ""]

    @staticmethod
    def _get_record_fields(record):
        return [f"{record.dnsName}", str(record.dnsTtl), "IN", record.recordType, str(record.rrData)]

    @staticmethod
    def _get_column_widths(rows):
        return [max(len(row[i]) for row in rows) for i in range(5)]

    @staticmethod
    def _format_row(fields, widths, tab_size=8):
        present = [i for i, f in enumerate(fields) if f]
        line, column = "", 0
        for i in present:
            field = fields[i]
            line += field
            column += len(field)
            if i == present[-1]:
                break
            target = Formatter._get_next_tab_stop(column + (widths[i] - len(field)), tab_size)
            if i == 0:
                target = Formatter._get_next_tab_stop(target, tab_size)
            tabs = 0
            while column < target:
                column = Formatter._get_next_tab_stop(column, tab_size)
                tabs += 1
            if tabs == 0:
                column = Formatter._get_next_tab_stop(column, tab_size)
                tabs = 1
            line += "\t" * tabs
        return line

    @staticmethod
    def get_dig_output(packet, intro_line=None):
        payload = packet.get_payload()
        header = payload.get_header()
        question = payload.get_question()
        answer = payload.get_answer()
        authority = payload.get_authority()
        additional = payload.get_additional()

        if intro_line is None:
            intro_line = "DnsClient (ip {}, port {}): Received DNS reply for queried name {}".format(packet.get_destination(), packet.get_destination_port(), question.dnsName)

        flags = []
        if header.get_dns_type() == DnsTypes.RESPONSE.value: flags.append("qr")
        if header.aa: flags.append("aa")
        if header.rd: flags.append("rd")
        if header.ra: flags.append("ra")

        out = intro_line + "\n"
        out += ";; Got answer:\n"
        out += f";; ->>HEADER<<- opcode: QUERY, status: {header.statusCode}, id: {header.queryId}\n"
        out += f";; flags: {' '.join(flags)}; QUERY: 1, ANSWER: {len(answer)}, AUTHORITY: {len(authority)}, ADDITIONAL: {len(additional)}\n"

        question_rows = [Formatter._get_question_fields(question)]
        answer_rows = [Formatter._get_record_fields(r) for r in answer]
        authority_rows = [Formatter._get_record_fields(r) for r in authority]
        additional_rows = [Formatter._get_record_fields(r) for r in additional]

        all_rows = question_rows + answer_rows + authority_rows + additional_rows
        widths = Formatter._get_column_widths(all_rows)

        out += f"\n;; QUESTION SECTION:\n"
        out += Formatter._format_row(question_rows[0], widths) + "\n"

        for section_name, rows in (("ANSWER", answer_rows), ("AUTHORITY", authority_rows), ("ADDITIONAL", additional_rows)):
            if rows:
                out += f"\n;; {section_name} SECTION:\n"
                for row in rows:
                    out += Formatter._format_row(row, widths) + "\n"

        out += "\n"
        return out

    @staticmethod
    def print_dig_output(packet, intro_line=None):
        print(Formatter.get_dig_output(packet, intro_line=intro_line), end="")
