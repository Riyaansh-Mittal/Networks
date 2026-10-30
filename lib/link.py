from packet import PacketTypes

class Link:
    _SENT = 0
    _RECV = 1
    _DROP = 2

    def __init__(self, n0, i0, n1, i1, linkId, prop, interface_ips=None):
        self._id = linkId
        self._node = [n0, n1]
        self._iface = [i0, i1]
        self._interface_ips = interface_ips if interface_ips else [None, None]
        self._properties = prop
        self._up = True
        self._in = [None, None]
        self._out = [None, None]
        self._in[0] = []
        self._out[0] = []
        self._in[1] = []
        self._out[1] = []

        self._counter = [[None, None], [None, None]]
        self._counter[0][self._SENT] = 0
        self._counter[0][self._RECV] = 0
        self._counter[1][self._SENT] = 0
        self._counter[1][self._RECV] = 0

    def get_interface_ip(self, iface_id):
        if iface_id == 0:
            return self._interface_ips[0]
        else:
            return self._interface_ips[1]

    def get_id(self):
        return self._id

    def get_node(self, id):
        if id == 0:
            return self._node[0]
        else:
            return self._node[1]

    def get_interface(self, id):
        if id == 0:
            return self._iface[0]
        else:
            return self._iface[1]

    def is_up(self):
        return self._up

    def set_state(self, s):
        self._up = s

    def get_properties(self):
        return self._properties

    def move_packets(self):
        p = None
        payload = None
        if self.is_up():
            while len(self._out[0]) > 0:
                p = self._out[0][0]
                if p.get_type() == PacketTypes.DATA.value:
                    payload = p.get_payload()
                    payload.add_entry("{}->{}".format(self._node[0], self._node[1]))
                    p.set_payload(payload)
                self._in[1].append(p)
                self._out[0].remove(p)
            while len(self._out[1]) > 0:
                p = self._out[1][0]
                if p.get_type() == PacketTypes.DATA.value:
                    payload = p.get_payload()
                    payload.add_entry("{}->{}".format(self._node[1], self._node[0]))
                    p.set_payload(payload)
                self._in[0].append(p)
                self._out[1].remove(p)

    def enqueue_packets(self, nodeid, p):
        if not self.is_up():
            print("Link {} is down: packet {} dropped".format(self,p))
            return False
        if nodeid == self._node[0]:
            self._out[0].append(p)
            self._counter[0][self._SENT] += 1
        else:
            self._out[1].append(p)
            self._counter[1][self._SENT] += 1
        return True

    def dequeue_packets(self, nodeid):
        p = None
        if nodeid == self._node[0]:
            if len(self._in[0]) > 0:
                p = self._in[0].pop(0)
                self._counter[0][self._RECV] += 1
                return p
        else:
            if len(self._in[1]) > 0:
                p = self._in[1].pop(0)
                self._counter[1][self._RECV] += 1
                return p
        return None

    def _get_description(self):
        s = "({0}.{1} <--> {2}.{3})".format(self._node[0], self._iface[0], self._node[1], self._iface[1])
        return s

    def __str__(self):
        return self._get_description()
