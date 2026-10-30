from abc import ABC, abstractmethod

class Application(ABC):
    def __init__(self, port):
        self._port = port
        self._verbose = False

    def set_verbose(self, value):
        self._verbose = value

    @abstractmethod
    def process_packet(self, packet):
        pass

    @abstractmethod
    def generate_packets(self):
        pass

    @abstractmethod
    def bind_to_host(self, endhost_id, endhost_ip):
        pass

    def set_parameters(self, parameters):
        pass

    def update(self, current_time, info_list):
        pass

class ClientApplication(Application):
    def trigger_send(self, args):
        pass

    def trigger_access_content(self, args):
        pass

import client_applications  # noqa: F401  (imported for its Application subclasses - see EndhostApplicationFactory)
import dns_servers  # noqa: F401  (imported for its Application subclasses - see EndhostApplicationFactory)

class EndhostApplicationFactory:
    @staticmethod
    def _get_all_subclasses(cls):
        for sub in cls.__subclasses__():
            yield sub
            yield from EndhostApplicationFactory._get_all_subclasses(sub)

    def __init__(self):
        self._availableApplications = {cls.__name__: cls for cls in self._get_all_subclasses(Application)}

    def get_application(self, appType, port):
        if appType not in self._availableApplications:
            print(f"Unrecognized application type: {appType}")
            exit(1)
        appClass = self._availableApplications[appType]
        return appClass(port)

