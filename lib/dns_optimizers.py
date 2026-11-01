
import json


class DnsConfigGenerator:
    def optimize(self, input_filename, output_filename):
        with open(input_filename, "r") as f:
            data = json.load(f)

        applications = data.setdefault("applications", [])
        endhosts = data.get("endhosts", [])
        links = data.get("network-links", [])
        events = data.get("events", [])

        host_ips = {
            host["eId"]: host["ipAddress"]
            for host in endhosts
        }

        # Match ContentClientRevenueChecker._build_host_delays().
        # The checker maps each host-facing interface IP to its link delay.
        # If an IP occurs on multiple links, the last matching link wins.
        network_id = data.get("network", {}).get("nId")
        delays = {}

        for link in links:
            interfaces = link.get("interfaces", [])
            interface_ips = link.get("interface_ips", [])
            delay = link.get("properties", {}).get("delay", 0)

            for side in (0, 1):
                if side >= len(interfaces) or side >= len(interface_ips):
                    continue

                node_id = interfaces[side].split("-")[0]

                if node_id != network_id:
                    delays[interface_ips[side]] = delay

        # Hosts running clients or local resolvers cannot host an ANS.
        forbidden_hosts = {
            app["eId"]
            for app in applications
            if app.get("type") in ("ContentClient", "LocalNameServer")
        }

        local_servers = [
            app for app in applications
            if app.get("type") == "LocalNameServer"
        ]

        # Find the simulation stop time for sessions without a duration.
        stop_times = [
            event.get("time", 0)
            for event in events
            if event.get("type") == "stop"
        ]
        simulation_end = max(stop_times) if stop_times else None

        # Collect requested DNS names and required server counts.
        requests = {}

        for event in events:
            if event.get("type") != "accesscontent":
                continue

            name = event.get("dnsName")
            if not name:
                continue

            request_time = event.get("time", 0)
            duration = event.get("duration")

            if duration is None:
                duration = max(
                    0,
                    simulation_end - request_time
                ) if simulation_end is not None else 0

            needed = event.get("neededServers", 1)

            entry = requests.setdefault(name, {
                "needed": 1,
                "sessions": []
            })

            entry["needed"] = max(entry["needed"], needed)
            entry["sessions"].append((
                request_time,
                request_time + duration
            ))

        # Calculate the maximum number of concurrent sessions per name.
        for entry in requests.values():
            sessions = entry["sessions"]
            max_concurrent = 0

            for start, _ in sessions:
                concurrent = sum(
                    1
                    for other_start, other_end in sessions
                    if other_start <= start < other_end
                )
                max_concurrent = max(max_concurrent, concurrent)

            entry["count"] = max(
                entry["needed"],
                max_concurrent,
                1
            )

        # Gather content-server IPs and their host-facing link delays.
        # The checker uses the endhost's primary IP to identify the
        # content-server host, then looks up that IP's link delay.
        candidates = []

        for host in endhosts:
            host_id = host["eId"]
            host_ip = host["ipAddress"]

            for ip in host.get("contentServers", []):
                candidates.append({
                    "host": host_id,
                    "host_ip": host_ip,
                    "ip": ip,
                    "delay": delays.get(host_ip, 0)
                })

        candidates.sort(
            key=lambda item: (
                item["delay"],
                item["host"],
                item["ip"]
            )
        )

        # A server-failure scenario benefits from host diversity.
        server_failures_enabled = any(
            event.get("type") == "allowserverfails"
            for event in events
        )

        # Assign each content-server IP to at most one DNS name.
        records = {}
        used_ips = set()

        for name in sorted(requests):
            count = requests[name]["count"]
            assigned = []

            if server_failures_enabled:
                used_hosts_for_name = set()

                # First select the fastest available IP on each distinct host.
                for candidate in candidates:
                    if len(assigned) >= count:
                        break
                    if candidate["ip"] in used_ips:
                        continue
                    if candidate["host"] in used_hosts_for_name:
                        continue

                    assigned.append({
                        "ip": candidate["ip"],
                        "ttl": 50
                    })
                    used_ips.add(candidate["ip"])
                    used_hosts_for_name.add(candidate["host"])

                # If more addresses are needed, use additional IPs.
                if len(assigned) < count:
                    for candidate in candidates:
                        if len(assigned) >= count:
                            break
                        if candidate["ip"] in used_ips:
                            continue

                        assigned.append({
                            "ip": candidate["ip"],
                            "ttl": 50
                        })
                        used_ips.add(candidate["ip"])

            else:
                # In failure-free scenarios, optimise for path delay.
                for candidate in candidates:
                    if len(assigned) >= count:
                        break
                    if candidate["ip"] in used_ips:
                        continue

                    assigned.append({
                        "ip": candidate["ip"],
                        "ttl": 50
                    })
                    used_ips.add(candidate["ip"])

            if assigned:
                records[name] = assigned

        # Find a legal host for the authoritative nameserver.
        hosts_with_port_53 = {
            app["eId"]
            for app in applications
            if app.get("port") == 53
        }

        eligible_hosts = [
            host for host in endhosts
            if host["eId"] not in forbidden_hosts
            and host["eId"] not in hosts_with_port_53
        ]

        ns_ip = None

        if eligible_hosts:
            ns_host = min(
                eligible_hosts,
                key=lambda host: (
                    delays.get(host["ipAddress"], 0),
                    host["eId"]
                )
            )

            ns_ip = host_ips[ns_host["eId"]]

            applications.append({
                "eId": ns_host["eId"],
                "type": "AuthoritativeNameServer",
                "port": 53,
                "parameters": {
                    "records A": records,
                    "zones": ["."]
                }
            })

        # Configure the root nameserver for every LocalNameServer.
        # If no legal ANS host exists, retain a fallback so the
        # generated configuration remains loadable.
        fallback_ip = (
            ns_ip
            if ns_ip is not None
            else next(iter(host_ips.values()), "127.0.0.1")
        )

        for app in local_servers:
            parameters = app.setdefault("parameters", {})
            parameters["root nameserver"] = {
                "name": ".",
                "ip": fallback_ip,
                "port": 53,
                "ttl": 50
            }

        with open(output_filename, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
