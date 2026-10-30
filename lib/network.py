from packet import PacketTypes

class Network:
    _DROP = 0
    _FORW = 1
    
    def __init__(self, nId):
        self._id = nId
        self._links = {}
        self._forwarding_table = {}
        self._counter = [0, 0]
        self._current_dns_packets = []
        self._current_traffic_packets = []
        print("Created network node {}".format(self.get_id()))

    def get_id(self):
        return self._id

    def get_dropped_traffic_packets(self):
        return self._counter[self._DROP]

    def get_forwarded_traffic_packets(self):
        return self._counter[self._FORW]

    def get_current_dns_packets(self):
        return self._current_dns_packets

    def get_current_traffic_packets(self):
        return self._current_traffic_packets

    def add_link(self, l):
        i0 = l.get_interface(0)
        n0 = l.get_node(0)
        i1 = l.get_interface(1)
        n1 = l.get_node(1)

        print("Adding link {} to {}".format(l, self._id))

        if (n0 == self._id):
            self._links[i0] = l
            neighbor_ip = l.get_interface_ip(1)
        elif (n1 == self._id):
            self._links[i1] = l
            neighbor_ip = l.get_interface_ip(0)
        else:
            return

        if neighbor_ip:
            self._forwarding_table[neighbor_ip] = i0 if n0 == self._id else i1

    def _send(self, p):
        dest_ip = p.get_destination()
        if p.get_type() == PacketTypes.DNS.value:
            self._current_dns_packets.append(p)
        else:
            self._current_traffic_packets.append(p)
        if dest_ip in self._forwarding_table:
            out_iface = self._forwarding_table[dest_ip]
            if out_iface in self._links:
                print("Network {}: Forwarding packet to {} over interface {}".format(self._id, dest_ip, out_iface))
                p.decrement_ttl()
                success = self._links[out_iface].enqueue_packets(self._id, p)
                if success:
                    self._counter[self._FORW] += 1
                else:
                    self._counter[self._DROP] += 1
            else:
                self._counter[self._DROP] += 1
                print("Network {}: Interface {} down or invalid".format(self._id, out_iface))
        else:
            self._counter[self._DROP] += 1
            print("Network {}: No route to destination {}".format(self._id, dest_ip))

    def dump_network(self):
        print("Network node {}:".format(self._id))
        print(" Interfaces: {}".format(list(self._links.keys())))
        print(" Forwarding Table: {}".format(self._forwarding_table))
        print(" Traffic Stats: fwd {} drop {}".format(self._counter[self._FORW], self._counter[self._DROP]))

    def go(self):
        self._current_dns_packets = []
        self._current_traffic_packets = []
        for iface in self._links:
            while True:
                p = self._links[iface].dequeue_packets(self._id)
                if p is None:
                    break
                self._send(p)
        return [], []
