from enum import Enum

class PacketTypes(Enum):    
    UNKNOWN = "unknown"            # unknown packet, used before a packet is classified.
    DATA = "data"                  # data packet
    DNS = "dns"                    # dns packet

class Payload:
    def __init__(self):
        self._data = list()
    
    def add_entry(self, o):
        self._data.append(str(o))

    def get_data(self):
        return self._data
  
    def __str__(self):
        return str(self._data)

class Packet:
    def __init__(self, s, d):
        self._src = s
        self._dst = d
        self._srcport = 50000
        self._dstport = 8080
        self._type = PacketTypes.UNKNOWN.value
        self._data = Payload()
        self._seq = 0
        self._ttl = 255

    def __str__(self):
        s = "type {} src {}:{} dst {}:{} ttl {} seq {}".format(self._type, self._src, self._srcport, self._dst, self._dstport, self._ttl, self._seq)
        if self._type == PacketTypes.DATA.value:
            if len(self._data.get_data()) > 0:
                s += " path"
                d = self._data.get_data()
                for i in d:
                    s += " ({})".format(i)
        else:
            s += " payload {}".format(self._data)
        return "<{}>".format(s)

    def __repr__(self):
        return str(self)

    def get_source(self):
        return self._src

    def get_destination(self):
        return self._dst

    def get_source_port(self):
        return self._srcport

    def get_destination_port(self):
        return self._dstport

    def get_type(self):
        return self._type;

    def get_sequence_number(self):
        return self._seq

    def get_payload(self):
        return self._data

    def get_ttl(self):
        return self._ttl

    def set_source(self, source_ip):
        self._src = source_ip

    def set_source_port(self, val):
        self._srcport = val

    def set_destination(self, dest_ip):
        self._dst = dest_ip

    def set_destination_port(self, val):
        self._dstport = val

    def set_sequence_number(self, s):
        self._seq = s

    def set_type(self, t):
        self._type = t

    def set_payload(self, d):
        if type(d) != Payload:
            raise Exception("ERROR: cannot set the payload of a packet to a type {}, different from {}".format(type(d),Payload))
        self._data = d

    def decrement_ttl(self):
        self._ttl -= 1

    def set_ttl(self,value):
        self._ttl = int(value)

class DnsTypes(Enum):
    QUERY = "QUERY"        # dns query
    RESPONSE = "RESPONSE"  # dns response

class DnsStatusCodes(Enum):
    NOERROR = "NOERROR"    # no error condition
    FORMERR = "FORMERR"    # the name server was unable to interpret the query
    SERVFAIL = "SERVFAIL"  # the name server was unable to process this query due to a problem with the name server
    NXDOMAIN = "NXDOMAIN"  # the domain name referenced in the query does not exist
    NOTIMP = "NOTIMP"      # the name server does not support the requested kind of query
    REFUSED = "REFUSED"    # the name server refuses to perform the specified operation for policy reasons

class DnsHeader:
    def __init__(self, queryId=None, resolutionId=None, dnsType=None, aa=False, rd=False, ra=False, statusCode=DnsStatusCodes.NOERROR.value):
        self.queryId = queryId
        self.resolutionId = resolutionId if resolutionId is not None else queryId
        self.set_dns_type(dnsType)
        self.aa = aa
        self.rd = rd
        self.ra = ra
        self.set_status_code(statusCode)

    def get_query_id(self): return self.queryId
    def set_query_id(self, val): self.queryId = val
    def get_resolution_id(self): return self.resolutionId
    def set_resolution_id(self, val): self.resolutionId = val
    def get_dns_type(self): return self.dnsType
    def set_dns_type(self, val):
        if val is not None and val not in {m.value for m in DnsTypes}:
            raise Exception("ERROR: cannot set the dnsType of a DnsHeader to {}, must be one of {}".format(val, [m.value for m in DnsTypes]))
        self.dnsType = val
    def get_aa(self): return self.aa
    def set_aa(self, val): self.aa = val
    def get_rd(self): return self.rd
    def set_rd(self, val): self.rd = val
    def get_ra(self): return self.ra
    def set_ra(self, val): self.ra = val
    def get_status_code(self): return self.statusCode
    def set_status_code(self, val):
        if val is not None and val not in {m.value for m in DnsStatusCodes}:
            raise Exception("ERROR: cannot set the statusCode of a DnsHeader to {}, must be one of {}".format(val, [m.value for m in DnsStatusCodes]))
        self.statusCode = val

    def __str__(self):
        return f"DnsHeader(queryId={self.queryId}, resolutionId={self.resolutionId}, dnsType={self.dnsType}, aa={self.aa}, rd={self.rd}, ra={self.ra}, statusCode={self.statusCode})"

class DnsQuestion:
    def __init__(self, dnsName=None, questionType=None):
        self.dnsName = dnsName
        self.questionType = questionType

    def get_dns_name(self): return self.dnsName
    def set_dns_name(self, val): self.dnsName = val
    def get_question_type(self): return self.questionType
    def set_question_type(self, val): self.questionType = val

    def __str__(self):
        return f"DnsQuestion(dnsName={self.dnsName}, questionType={self.questionType})"

class DnsResourceRecord:
    def __init__(self, dnsName=None, recordType=None, dnsTtl=None, rrData=None):
        self.dnsName = dnsName
        self.recordType = recordType
        self.dnsTtl = dnsTtl
        self.rrData = rrData

    def get_dns_name(self): return self.dnsName
    def set_dns_name(self, val): self.dnsName = val
    def get_record_type(self): return self.recordType
    def set_record_type(self, val): self.recordType = val
    def get_dns_ttl(self): return self.dnsTtl
    def set_dns_ttl(self, val): self.dnsTtl = val
    def get_rr_data(self): return self.rrData
    def set_rr_data(self, val): self.rrData = val

    def __str__(self):
        return f"DnsResourceRecord(dnsName={self.dnsName}, recordType={self.recordType}, dnsTtl={self.dnsTtl}, rrData={self.rrData})"
    __repr__ = __str__

class DnsPayload(Payload):
    def __init__(self, header=None, question=None, answer=None, authority=None, additional=None):
        super().__init__()
        self.header = header
        self.question = question
        self.set_answer(answer)
        self.set_authority(authority)
        self.set_additional(additional)

    def get_header(self): return self.header
    def set_header(self, val):
        if not isinstance(val, DnsHeader):
            raise Exception("ERROR: cannot set the header of a DnsPayload to a type {}, different from {}".format(type(val), DnsHeader))
        self.header = val
    def get_question(self): return self.question
    def set_question(self, val):
        if not isinstance(val, DnsQuestion):
            raise Exception("ERROR: cannot set the question of a DnsPayload to a type {}, different from {}".format(type(val), DnsQuestion))
        self.question = val
    def get_answer(self): return self.answer
    def set_answer(self, val):
        if val is None:
            val = []
        if not isinstance(val, list) or not all(isinstance(r, DnsResourceRecord) for r in val):
            raise Exception("ERROR: cannot set the answer of a DnsPayload to a type {}, must be a list of {}".format(type(val), DnsResourceRecord))
        self.answer = val
    def get_authority(self): return self.authority
    def set_authority(self, val):
        if val is None:
            val = []
        if not isinstance(val, list) or not all(isinstance(r, DnsResourceRecord) for r in val):
            raise Exception("ERROR: cannot set the authority of a DnsPayload to a type {}, must be a list of {}".format(type(val), DnsResourceRecord))
        self.authority = val
    def get_additional(self): return self.additional
    def set_additional(self, val):
        if val is None:
            val = []
        if not isinstance(val, list) or not all(isinstance(r, DnsResourceRecord) for r in val):
            raise Exception("ERROR: cannot set the additional of a DnsPayload to a type {}, must be a list of {}".format(type(val), DnsResourceRecord))
        self.additional = val

    def get_data(self):
        return [self.header, self.question, self.answer, self.authority, self.additional]

    def __str__(self):
        return f"DnsPayload(header={self.header}, question={self.question}, answer={self.answer}, authority={self.authority}, additional={self.additional})"

    def get_summary(self):
        kind = "query" if self.header.get_dns_type() == DnsTypes.QUERY.value else "reply"
        return "DNS {} for {}".format(kind, self.question.get_dns_name())

class DnsPacket(Packet):
    def __init__(self, src, dst):
        super().__init__(src, dst)
        self._type = PacketTypes.DNS.value
        self._srcport = 53
        self._dstport = 53

    def __str__(self):
        s = "type {} src {}:{} dst {}:{}".format(self._type, self._src, self._srcport, self._dst, self._dstport)
        s += " payload {}".format(self._data.get_summary())
        return "<{}>".format(s)

    def set_source_port(self, val):
        self._srcport = val

    def set_destination_port(self, val):
        self._dstport = val

    def set_payload(self, d):
        if not isinstance(d, DnsPayload):
            raise Exception("ERROR: cannot set the payload of a DnsPacket to a type {}, different from {}".format(type(d), DnsPayload))
        self._data = d

