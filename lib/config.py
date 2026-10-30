import hashlib
import json

from network import Network
from link import Link
from event import Event
from checkers import ForwardingChecker, DnsChecker, ContentClientRevenueChecker, DnsClientRevenueChecker
from endhost import EndHost
from endhost_application import EndhostApplicationFactory
from utils import ContentServerMonitor

import os

class ConfigParser:
    def __init__(self, filename, s):
        self._filename = filename
        self._seed_filename = s.get_original_config_filename()
        self._network = None
        self._endhosts = []
        self._events = []
        self._links = []
        self._contentServersMonitors = []
        self._sim = s
        print(f"Reading file {filename}")
        with open(filename, 'rt') as f:
            content = f.read()
        configData = json.loads(content) if content.strip() else {}
        self._process(configData)
        self._sim.add_network(self._network)
        self._sim.add_endhosts(self._endhosts)
        self._sim.add_links(self._links)
        self._sim.add_events(self._events)
        self._sim.add_content_server_monitors(self._contentServersMonitors)

    def _process(self, configData):
        lns_ips = set()
        ns_ips = set()
        client_ips = set()
        lns_ip_ports = set()          # set of (ip, port) pairs actually bound to a LocalNameServer application
        ns_ip_ports = set()           # set of (ip, port) pairs actually bound to an AuthoritativeNameServer application
        dns_client_ips = set()        # set of IPs running a plain DnsClient application
        content_clients = {}          # dict: client_app_id (i.e. (client_ip, port)) -> its ContentClient application
        configured_dns_records = {}   # dict: dns_name -> set of every IP it's configured to resolve to, read directly off each AuthoritativeNameServer's own "records A" config entry
        configured_records_by_ns = {} # dict: NS ip -> set of (name, type, data) A/CNAME records that NS's config declares (incl. the glue A record of any "records NS" entry)
        configured_record_ttls_by_ns = {}   # dict: NS ip -> {(name, type, data): TTL that NS's config pins for it}

        if configData:
            if 'network' not in configData:
                print("Configuration file must specify exactly one network")
                exit(1)
            net = configData['network']
            self._network = Network(nId=net['nId'])

            if 'endhosts' in configData:
                for endhost in configData['endhosts']:
                    eId = endhost['eId']
                    eIP = endhost['ipAddress']
                    eh = EndHost(
                        eId=eId,
                        ipAddress=eIP
                    )
                    self._endhosts.append(eh)
                    if 'contentServers' in endhost:
                        seed = self._get_deterministic_seed(eId)
                        self._contentServersMonitors.append(ContentServerMonitor(eh, endhost['contentServers'], seed=seed))
            
            if 'applications' in configData:
                for app_conf in configData['applications']:
                    eh = None
                    for candidate in self._endhosts:
                        if candidate.get_id() == app_conf['eId']:
                            eh = candidate
                            break
                    if eh:
                        app = EndhostApplicationFactory().get_application(app_conf['type'], app_conf['port'])
                        eh.set_application(app)
                        if 'parameters' in app_conf:
                            app.set_parameters(app_conf['parameters'])
                        if app_conf['type'] == 'ContentClient':
                            client_ips.add(eh.get_ip())
                            content_clients[(eh.get_ip(), app_conf['port'])] = app
                        elif app_conf['type'] == 'DnsClient':
                            client_ips.add(eh.get_ip())
                            dns_client_ips.add(eh.get_ip())
                        elif app_conf['type'].startswith('AuthoritativeNameServer'):
                            ns_ips.add(eh.get_ip())
                            ns_ip_ports.add((eh.get_ip(), app_conf['port']))
                            records_a = app_conf.get('parameters', {}).get('records A', {})
                            for name, records in records_a.items():
                                configured_dns_records.setdefault(name, set()).update(record['ip'] for record in records)
                            recs, rec_ttls = self._get_authoritative_records(app_conf.get('parameters', {}))
                            ns_ip = eh.get_ip()
                            configured_records_by_ns.setdefault(ns_ip, set()).update(recs)
                            ns_ttls = configured_record_ttls_by_ns.setdefault(ns_ip, {})
                            for triple, ttl in rec_ttls.items():
                                ns_ttls[triple] = max(ns_ttls.get(triple, ttl), ttl)
                        elif app_conf['type'] == 'LocalNameServer':
                            lns_ips.add(eh.get_ip())
                            lns_ip_ports.add((eh.get_ip(), app_conf['port']))
                    else:
                        print(f"Application specified for non-existing host: {app_conf['eId']}")
                        exit(1)

            if 'network-links' in configData:
                for link in configData['network-links']:
                    n0 = link['interfaces'][0].split('-')[0]
                    n1 = link['interfaces'][1].split('-')[0]
                    conf_props = {}
                    if 'properties' in link:
                        conf_props = link['properties']

                    interface_ips = None
                    if 'interface_ips' in link:
                        interface_ips = link['interface_ips']

                    l = Link(
                        n0=n0,
                        i0=link['interfaces'][0],
                        n1=n1,
                        i1=link['interfaces'][1],
                        linkId=link['id'],
                        prop=conf_props,
                        interface_ips=interface_ips,
                    )
                    if link['status'] == "up":
                        l.set_state(True)
                    elif link['status'] == "down":
                        l.set_state(False)
                    else:
                        print(f"Unknown link state {link['status']}")
                    self._links.append(l)

            for event in configData['events']:
                if event['type'] == "uplink" or event['type'] == "downlink":
                    e = Event(event['type'], int(event['time']), event['link'])
                    self._events.append(e)

                elif event['type'] == "stop":
                    self._sim.set_stop_time(int(event['time']))

                elif event['type'] == "dumpnetwork":
                    args = []
                    args.append(event['args'])
                    e = Event(event['type'], int(event['time']), args)
                    self._events.append(e)

                elif event['type'] == "sendquery":
                    args = [event['src'], event['src_port'], event['dst'], event['dst_port'], event['dnsName'], event['questionType']]
                    e = Event(event['type'], int(event['time']), args)
                    self._events.append(e)

                elif event['type'] == "accesscontent":
                    args = [event['src'], event['src_port'], event['dst'], event['dst_port'], event['dnsName'], event['questionType'], event.get('neededServers', 1), event.get('duration', 50)]
                    e = Event(event['type'], int(event['time']), args)
                    self._events.append(e)

                elif event['type'] == "allowserverfails":
                    e = Event(event['type'], int(event['time']), [])
                    self._events.append(e)

                elif event['type'] == "sendpackets":
                    args = [event['src'], event['src_port'], event['dst'], event['dst_port'], event['num_packets']]
                    e = Event(event['type'], int(event['time']), args)
                    self._events.append(e)

                else:
                    print(f"Unrecognized event: {event}")
                    exit(1)
        else:
            self._network = Network(nId="empty")

        fwdchecker = ForwardingChecker(self._network)
        dnschecker = DnsChecker(self._network, self._endhosts, lns_ips, ns_ips, client_ips,
                                configured_records_by_ns=configured_records_by_ns,
                                configured_record_ttls_by_ns=configured_record_ttls_by_ns,
                                lns_ip_ports=lns_ip_ports, ns_ip_ports=ns_ip_ports)
        simcheckers = [fwdchecker, dnschecker]
        if content_clients or not configData:
            revenuechecker = ContentClientRevenueChecker(self._network, self._links, self._endhosts, self._contentServersMonitors, content_clients, configured_dns_records)
            simcheckers.append(revenuechecker)
        elif dns_client_ips or not configData:
            dns_client_revenue_checker = DnsClientRevenueChecker(self._network, self._endhosts, dns_client_ips)
            simcheckers.append(dns_client_revenue_checker)
        self._sim.set_checkers(simcheckers)

    @staticmethod
    def _get_authoritative_records(parameters):
        records = set()
        ttls = {}
        def add(triple, ttl):
            records.add(triple)
            if ttl is not None:
                ttls[triple] = max(ttls.get(triple, ttl), ttl)
        for name, entries in (parameters.get("records A") or {}).items():
            for entry in entries:
                add((name, "A", entry["ip"]), entry["ttl"])
        for name, entries in (parameters.get("records CNAME") or {}).items():
            for entry in entries:
                add((name, "CNAME", entry["alias"]), entry["ttl"])
        for entries in (parameters.get("records NS") or {}).values():
            for entry in entries:
                if "name" in entry and "ip" in entry:
                    add((entry["name"], "A", entry["ip"]), entry.get("ipttl"))
        return records, ttls

    _SEED_SALT = 51

    def _get_deterministic_seed(self, eId):
        config_name_length = len(os.path.basename(self._seed_filename))
        digest = hashlib.sha256("{}:{}:{}".format(config_name_length, eId, self._SEED_SALT).encode()).hexdigest()
        return int(digest, 16) % (2 ** 32)

