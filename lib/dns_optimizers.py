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

        # Hosts whose link is down at any time are unsafe for ANS / content servers
        down_ifaces = set()
        for event in events:
            if event.get("type") == "downlink":
                down_ifaces.update(event.get("link", []))
        down_hosts = set()
        for link in links:
            for side in link.get("interfaces", []):
                if side in down_ifaces:
                    for other in link.get("interfaces", []):
                        if other.split("-")[0] != network_id:
                            down_hosts.add(other.split("-")[0])

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
            # Nameservers treat names case-insensitively and with or without
            # the trailing dot as the same name: merge those spellings.
            name = name.strip().lower()
            if not name.endswith("."):
                name += "."

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
            entry.setdefault("detail", []).append(
                (request_time, request_time + duration, needed))

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

            peak = 0
            for start, _ in sessions:
                peak = max(peak, sum(
                    n for (s0, e0, n) in entry["detail"] if s0 <= start < e0))
            entry["count"] = max(peak, 1)

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
                    "delay": delays.get(host_ip, 0),
                    "down": host_id in down_hosts
                })

        candidates.sort(
            key=lambda item: (
                item["down"],
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

        # Record TTL. Clients re-query (and sit without a path while the
        # name is re-resolved) every TTL steps, so a long TTL is best when
        # nothing can go wrong. When servers may fail or links go down, a
        # moderate TTL limits how long a client keeps a dead server without
        # paying for constant re-resolution.
        has_downlink = any(e.get("type") == "downlink" for e in events)
        ttl_value = 50 if (server_failures_enabled or has_downlink) else 3600

        # Assign each content-server IP to at most one DNS name.
        # Every requested name first gets one server (an unresolved name is
        # far more costly than an overloaded server); remaining servers are
        # then distributed up to each name's peak need, busiest names first.
        records = {}
        used_ips = set()
        hosts_used = {}

        def demand(name):
            return sum((e0 - s0) * n for (s0, e0, n) in requests[name]["detail"])

        order = sorted(requests, key=lambda n: (-demand(n), n))

        def pick(name):
            chosen = None
            # Servers behind a downed link only hurt (-100/step each);
            # use them only when a name would otherwise have no server.
            allow_down = not records.get(name)
            if server_failures_enabled:
                # prefer a host not already serving this name
                for candidate in candidates:
                    if candidate["down"] and not allow_down:
                        continue
                    if candidate["ip"] in used_ips:
                        continue
                    if candidate["host"] in hosts_used.setdefault(name, set()):
                        continue
                    chosen = candidate
                    break
            if chosen is None:
                for candidate in candidates:
                    if candidate["down"] and not allow_down:
                        continue
                    if candidate["ip"] not in used_ips:
                        chosen = candidate
                        break
            if chosen is None:
                return False
            used_ips.add(chosen["ip"])
            hosts_used.setdefault(name, set()).add(chosen["host"])
            records.setdefault(name, []).append({"ip": chosen["ip"], "ttl": ttl_value})
            return True

        for name in order:
            pick(name)
        for name in order:
            while len(records.get(name, [])) < requests[name]["count"]:
                if not pick(name):
                    break

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
        reachable = [h for h in eligible_hosts if h["eId"] not in down_hosts]
        if reachable:
            eligible_hosts = reachable

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

        if requests and (ns_ip is None or not candidates):
            # No legal host can run an AuthoritativeNameServer (every host
            # runs a client / resolver or already uses port 53), so no valid
            # DNS hierarchy exists. An empty output is the simulator's
            # supported way to say "nothing to optimise"; it avoids a
            # configuration whose resolutions can never complete.
            open(output_filename, "w").close()
            return

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