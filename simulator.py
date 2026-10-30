import os, sys, argparse
dirpath = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(dirpath,'lib'))

from config import ConfigParser
from dns_optimizers import DnsConfigGenerator
from checkers import ConfigOptimizationChecker

class Simulator:
    @staticmethod
    def _is_config_empty(filename):
        try:
            with open(filename, 'rt') as f:
                return f.read().strip() == ""
        except FileNotFoundError:
            return False

    def __init__(self, configFile, optimized_config_file=None):
        self._config_file = configFile
        self._original_config_file = configFile
        self._stop_time = 1
        self._endhosts = {}
        self._events = []
        self._links = []
        self._checkers = []
        self._content_server_monitors = []
        if optimized_config_file:
            print("\n** DNS Optimization **\n")
            DnsConfigGenerator().optimize(self._config_file, optimized_config_file)
            if self._is_config_empty(optimized_config_file):
                print("Optimized configuration {} is empty - nothing to check against {}.\n".format(
                    optimized_config_file, configFile))
            else:
                config_optimization_checker = ConfigOptimizationChecker(self._config_file, optimized_config_file)
                config_optimization_checker.print_report()
                if config_optimization_checker.has_errors():
                    print("\n+++ ERROR: optimized configuration {} failed validation against {} - aborting +++\n".format(
                        optimized_config_file, self._config_file))
                    sys.exit(1)
            self._config_file = optimized_config_file
        self._input_is_empty = self._is_config_empty(self._config_file)
        print("\n** Configuration Loading **\n")
        ConfigParser(self._config_file, self)

    def get_original_config_filename(self):
        return self._original_config_file

    def add_network(self, network):
        self._network = network

    def add_content_server_monitors(self, monitors):
        self._content_server_monitors = monitors

    def __str__(self):
        return "Network Simulator"

    def set_stop_time(self, t):
        self._stop_time = t

    def set_checkers(self, checkers_list):
        self._checkers = checkers_list

    def set_verbose(self, value):
        for checker in self._checkers:
            checker.set_verbose(value)
        for eh in self._endhosts.values():
            eh.set_verbose(value)

    def add_endhosts(self, ehs):
        self._endhosts = {}
        for eh in ehs:
            self._endhosts[eh.get_id()] = eh

    def add_events(self, e):
        self._events = []
        for eobj in e:
            print("Adding {}".format(eobj))
            self._events.append(eobj)

    def add_links(self, links2add):
        self._links = []
        for l in links2add:
            self._links.append(l)
        for i in range(len(self._links)):
            n0 = self._links[i].get_node(0)
            n1 = self._links[i].get_node(1)

            def get_node(nodeId):
                if nodeId in self._endhosts:
                    return self._endhosts[nodeId]
                elif hasattr(self, '_network') and self._network and self._network.get_id() == nodeId:
                    return self._network
                return None

            node0 = get_node(n0)
            node1 = get_node(n1)

            if node0:
                node0.add_link(self._links[i])
            if node1:
                node1.add_link(self._links[i])

    def process_networks(self, now):
        dlog = []
        if hasattr(self, '_network') and self._network:
            (dlist, _) = self._network.go()
            dlog += dlist
        return dlog

    def process_content_server_monitors(self, now):
        for monitor in self._content_server_monitors:
            monitor.update_statuses()

    def main_loop(self):
        now = 1
        print("\n\n** Simulation **")
        if self._input_is_empty:
            print("\nNothing to simulate: the input configuration file is empty.")
        while(now < self._stop_time):
            print("\n= Time {} =".format(now))
            self.process_events(now)
            self.process_content_server_monitors(now)
            datalog = self.process_networks(now)
            datalog += self.process_endhosts(now)
            self.process_packets()
            if len(datalog) > 0:
                print("\n".join(datalog) + "\n")
            self.check_iteration(now)
            now += 1
        self.check_completed()
        self.print_report()

    def process_events(self, now):
        event = None
        add_empty_line = False

        print()
        for count in range(len(self._events)):
            event = self._events[count]

            if ((event.get_time() <= now) and (event.get_state() != True)):
                add_empty_line = True
                if event.get_operation() == "uplink":
                    for i in range(len(self._links)):
                       if (self._links[i].get_interface(0) == event.get_argument(0) and (self._links[i].get_interface(1) == event.get_argument(1))):
                            print("Setting link {} UP".format(self._links[i]))
                            self._links[i].set_state(True)
                            break

                elif event.get_operation() == "downlink":
                    for i in range(len(self._links)):
                        if (self._links[i].get_interface(0) == event.get_argument(0) and (self._links[i].get_interface(1) == event.get_argument(1))):
                            print("Setting link {} DOWN".format(self._links[i]))
                            self._links[i].set_state(False)
                            break

                elif event.get_operation() == "dumpnetwork":
                    print("{}".format(event))
                    if event.get_argument(0) == "all" or (hasattr(self, '_network') and self._network.get_id() == event.get_argument(0)):
                        if hasattr(self, '_network'):
                            self._network.dump_network()
                    add_empty_line = False

                elif event.get_operation() == "allowserverfails":
                    print("{}".format(event))
                    for monitor in self._content_server_monitors:
                        monitor.activate_random_failures()

                elif event.get_operation() == "sendpackets":
                    print("{}".format(event))
                    src = event.get_argument(0)
                    src_port = event.get_argument(1)
                    dst = event.get_argument(2)
                    dst_port = event.get_argument(3)
                    num_packets = int(event.get_argument(4))
                    args = [dst, dst_port, num_packets]
                    found = False
                    for eh in self._endhosts.values():
                        if eh.get_ip() == src and eh.trigger_app_send(src_port, args):
                            found = True
                            break
                    if not found:
                        print("+++ ERROR: Could not find application {}:{} to send packets +++".format(src, src_port))
                        sys.exit(1)

                elif event.get_operation() == "sendquery":
                    print("{}".format(event))
                    src = event.get_argument(0)
                    src_port = event.get_argument(1)
                    dst = event.get_argument(2)
                    dst_port = event.get_argument(3)
                    dnsName = event.get_argument(4)
                    questionType = event.get_argument(5)
                    args = [dst, dst_port, dnsName, questionType]
                    found = False
                    for eh in self._endhosts.values():
                        if eh.get_ip() == src and eh.trigger_app_send(src_port, args):
                            found = True
                            break
                    if not found:
                        print("+++ ERROR: Could not find application {}:{} to send query +++".format(src, src_port))
                        sys.exit(1)

                elif event.get_operation() == "accesscontent":
                    print("{}".format(event))
                    src = event.get_argument(0)
                    src_port = event.get_argument(1)
                    dst = event.get_argument(2)
                    dst_port = event.get_argument(3)
                    dnsName = event.get_argument(4)
                    questionType = event.get_argument(5)
                    neededServers = event.get_argument(6) if event.get_number_of_arguments() > 6 else 1
                    duration = event.get_argument(7) if event.get_number_of_arguments() > 7 else 50
                    args = [dst, dst_port, dnsName, questionType, neededServers, duration]
                    found = False
                    for eh in self._endhosts.values():
                        if eh.get_ip() == src and eh.trigger_app_access_content(src_port, args):
                            found = True
                            break
                    if not found:
                        print("+++ ERROR: Could not find application {}:{} to access content +++".format(src, src_port))
                        sys.exit(1)

                else:
                    print("\n+++ ERROR: Simulator received event {} which is unable to handle: aborting +++\n".format(event))
                    sys.exit(1)

                self._events[count].set_done()

        if add_empty_line:
            print()

    def process_endhosts(self, now):
        dlog = []
        for eId in self._endhosts:
            self._endhosts[eId].set_time_step(now)
            (dlist, _) = self._endhosts[eId].go()
            dlog += dlist
        return dlog
        
    def process_packets(self):
        for i in range(len(self._links)):
            self._links[i].move_packets()

    def check_iteration(self, time):
        for checker in self._checkers:
            checker.check(time)

    def check_completed(self):
        unused_events = 0
        for i in range(len(self._events)):
            if (self._events[i].get_state() != True):
                unused_events += 1
        if (unused_events > 0):
            print("\n+++ WARNING: stopping now but {} events not simulated! +++".format(unused_events))
    
    def print_report(self):
        print("\n\n** Simulation Report **\n")
        for checker in self._checkers:
            checker.print_report()
            print()
        print()

def main():
    parser = argparse.ArgumentParser(description='NETS Simulator.')
    parser.add_argument("-v", "--verbose", action='store_true', default=False,
                        help='Runs the simulator in verbose mode', required=False)
    parser.add_argument("-c", "--config_file", type=str, required=True,
                        help='Sets the configuration file for the simulation')
    parser.add_argument("-o", "--optimized_config_file", type=str, default=None,
                        help='If set, runs the DNS optimizer on the config file first, writing the '
                             'optimized configuration to this file, and simulates that instead',
                        required=False)
    args = parser.parse_args()

    sim = Simulator(args.config_file, optimized_config_file=args.optimized_config_file)
    sim.set_verbose(args.verbose)
    sim.main_loop()
    
if __name__=="__main__":
    main()
