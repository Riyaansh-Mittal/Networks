class EndHost:
    def __init__(self, eId, ipAddress):
        self._id = eId
        self._ip = ipAddress
        self._links = {}
        self._verbose = False
        self._apps = []
        self._current_time = 0
        self._content_server_status_updates = {}  # dict: content-server ip -> most recently received upcoming-statuses list
        self._pending_status_updates = []  # info dicts queued by receive_content_server_status_update, delivered to apps via update() at the start of the next go()
        print("Created end-host {}".format(self.get_id()))

    def get_id(self):
        return self._id

    def get_ip(self):
        return self._ip

    def add_link(self, l):
        i0 = l.get_interface(0)
        n0 = l.get_node(0)
        i1 = l.get_interface(1)
        n1 = l.get_node(1)
        print("Adding link {} to end-host {}".format(l, self._id))
        if (n0 == self._id):
            self._links[i0] = l
        elif (n1 == self._id):
            self._links[i1] = l

    def set_application(self, app):
        self._apps.append(app)
        app.bind_to_host(self._id, self._ip)

    def trigger_app_send(self, port, args):
        for app in self._apps:
            if app._port == port:
                app.trigger_send(args)
                return True
        return False

    def trigger_app_access_content(self, port, args):
        for app in self._apps:
            if app._port == port:
                app.trigger_access_content(args)
                return True
        return False

    def set_time_step(self, time):
        self._current_time = int(time)

    def receive_content_server_status_update(self, ip, upcoming_statuses):
        statuses = list(upcoming_statuses)
        self._content_server_status_updates[ip] = statuses
        if self._verbose:
            print("End-host {}: received content server status update for {}: {}".format(
                self._id, ip, statuses))
        info = {"type": "contentServerStatus", "ip": ip, "statuses": statuses}
        self._pending_status_updates.append(info)

    def set_verbose(self, value):
        self._verbose = value
        for app in self._apps:
            app.set_verbose(value)
        
    def _send(self, packet):
        if not self._links:
            print("End-host {} has no links to send!".format(self._id))
            return
        link = list(self._links.values())[0]
        link.enqueue_packets(self._id, packet)

    def go(self):
        updates = self._pending_status_updates
        self._pending_status_updates = []
        info_list = updates if updates else None
        for app in self._apps:
            app.update(self._current_time, info_list)
        datalog = self._process_packets()
        for app in self._apps:
            pkts = app.generate_packets()
            if pkts:
                for pkt in pkts:
                    self._send(pkt)
        return (datalog, [])

    def _process_packets(self):
        outlog = []
        for iface in self._links:
            while True:
                p = self._receive(iface)
                if p is None:
                    break
                
                dst_port = p.get_destination_port()
                for app in self._apps:
                    if app._port == dst_port:
                        app.process_packet(p)
                        break
        return outlog

    def _receive(self, iface):
        return self._links[iface].dequeue_packets(self._id)
