import heapq
import json
import math
import random
import time

# Timing the model uses for DNS resolution (simulation steps): a cold
# resolution takes ~8 steps, an answer already cached by the resolver ~4.
_COLD, _WARM = 8, 4
_SEARCH_SECONDS = 1.0


class _RevenueModel:
    """Small re-implementation of the content-client revenue rules.

    A session with load L spreads L units over the first A records of the
    answer it received; a server carrying more than one unit for the same
    client and name costs -25 per step for each session using it; a server
    behind a down link costs -100; otherwise a server earns
    100 * (average delay - path delay) / average delay per step.
    """

    FAIL_P, RECOVER_P = 0.01, 0.05   # content-server failure / recovery per step

    def __init__(self, avg_delay, down_intervals, ttl, fail_from=None):
        self.avg = avg_delay
        self.down = down_intervals
        self.ttl = ttl
        self.fail_from = fail_from

    def _failed_fraction(self, t):
        # Probability that a content server is in the failed state at time t.
        if self.fail_from is None or t <= self.fail_from:
            return 0.0
        rate = self.FAIL_P + self.RECOVER_P
        return (self.FAIL_P / rate) * (1.0 - math.exp(-rate * (t - self.fail_from)))

    def step_revenue(self, delay):
        if self.avg == 0:
            return 100.0 if delay == 0 else -100.0
        return round(100.0 * (self.avg - delay) / self.avg, 2)

    def _is_down(self, host, t):
        for a, b in self.down.get(host, ()):
            if a <= t < b:
                return True
        return False

    def value(self, sessions, servers):
        n = len(servers)
        if n == 0:
            return -200.0 * sum(max(0, e - s) for s, e, *_rest in sessions)
        ttl = max(1, self.ttl)
        heap = [(s, k, 0) for k, (s, e, *_rest) in enumerate(sessions) if e > s]
        heapq.heapify(heap)
        pieces = []
        fixed = 0.0
        # Every local resolver has its own cache and its own rotation counter.
        state = {}
        while heap:
            t, k, p = heapq.heappop(heap)
            s, e, load, ckey, cdelay, lns = sessions[k]
            st = state.setdefault(lns, {"done": None, "count": 0})
            res_done = st["done"]
            if res_done is not None and t + 2 < res_done:
                reply = res_done
            elif res_done is not None and t + 2 < res_done + ttl:
                reply = t + _WARM
            else:
                res_done = t + _COLD
                st["done"] = res_done
                reply = res_done
            if p == 0:
                if reply >= e:
                    fixed += -200.0 * (e - s)   # never answered while live
                else:
                    fixed += -5.0 * (reply - s)  # waiting for the first answer
            else:
                # a renewal is a new query: waiting for it costs -5 per step
                fixed += -5.0 * (min(reply, e) - t)
            rot = st["count"] % n if n >= 2 else 0
            st["count"] += 1
            base, rem = divmod(load, n)
            shares = {}
            for i in range(n):
                share = base + (1 if i < rem else 0)
                if share > 0:
                    shares[(rot + i) % n] = share
            # An answer served from the resolver's cache carries the TTL that
            # is left, so every session renews when that cache entry expires.
            expiry = st["done"] + ttl
            end = min(expiry, e)
            if reply < end:
                pieces.append((reply, end, ckey, cdelay, shares))
            if expiry < e:
                heapq.heappush(heap, (max(expiry, reply), k, p + 1))
        if not pieces:
            return fixed
        points = set()
        for a, b, _c, _d, _s in pieces:
            points.add(a)
            points.add(b)
        for server in servers:
            for a, b in self.down.get(server[1], ()):
                points.add(a)
                if b != float("inf"):
                    points.add(b)
        points = sorted(points)
        total = fixed
        for a, b in zip(points, points[1:]):
            active = [pc for pc in pieces if pc[0] <= a < pc[1]]
            if not active:
                continue
            by_client = {}
            for pc in active:
                by_client.setdefault(pc[2], []).append(pc)
            seg = 0.0
            for plist in by_client.values():
                merged = {}
                for pc in plist:
                    for idx, share in pc[4].items():
                        merged[idx] = merged.get(idx, 0) + share
                for pc in plist:
                    for idx in pc[4]:
                        if merged[idx] > 1:
                            seg += -25.0 - 100.0 * self._failed_fraction((a + b) / 2.0)
                        elif self._is_down(servers[idx][1], a):
                            seg += -100.0
                        else:
                            rev = self.step_revenue(pc[3] + servers[idx][2])
                            f = self._failed_fraction((a + b) / 2.0)
                            seg += rev * (1.0 - f) - 100.0 * f
            total += seg * (b - a)
        return total


def _improve_allocation(names, sessions, starts, pool, model, budget):
    """Search for the content-server allocation with the best modelled revenue.

    starts: list of allocations (name -> ordered list of servers); pool:
    every server as (ip, host, delay). Each start is improved by local search
    (move / replace / swap / reorder); extra random restarts use whatever time
    is left. Returns (best score, best allocation).
    """
    deadline = time.perf_counter() + budget
    memo = {}

    def val(name, lst):
        key = (name, tuple(s[0] for s in lst))
        if key not in memo:
            memo[key] = model.value(sessions[name], lst)
        return memo[key]

    def local(assign):
        owner = {}
        for name in names:
            for srv in assign[name]:
                owner[srv[0]] = name
        cur = {name: val(name, assign[name]) for name in names}
        improved = True
        while improved and time.perf_counter() < deadline:
            improved = False
            # move a server to another name (or release it)
            for srv in pool:
                if time.perf_counter() > deadline:
                    break
                src = owner.get(srv[0])
                moved = False
                for dst in names + [None]:
                    if dst == src:
                        continue
                    src_list = ([x for x in assign[src] if x[0] != srv[0]]
                                if src else None)
                    options = [None] if dst is None else [
                        assign[dst] + [srv], [srv] + assign[dst]]
                    for new_dst in options:
                        delta = 0.0
                        if src:
                            delta += val(src, src_list) - cur[src]
                        if dst is not None:
                            delta += val(dst, new_dst) - cur[dst]
                        if delta > 1e-6:
                            if src:
                                assign[src] = src_list
                                cur[src] = val(src, src_list)
                            if dst is not None:
                                assign[dst] = new_dst
                                cur[dst] = val(dst, new_dst)
                                owner[srv[0]] = dst
                            else:
                                owner.pop(srv[0], None)
                            improved = moved = True
                            break
                    if moved:
                        break
            # replace a server of a name by an unused one; reorder inside a name
            for name in names:
                if time.perf_counter() > deadline:
                    break
                done = False
                for i, old in enumerate(assign[name]):
                    for new in pool:
                        if new[0] in owner:
                            continue
                        cand = list(assign[name])
                        cand[i] = new
                        if val(name, cand) - cur[name] > 1e-6:
                            owner.pop(old[0], None)
                            owner[new[0]] = name
                            assign[name] = cand
                            cur[name] = val(name, cand)
                            improved = done = True
                            break
                    if done:
                        break
                if done:
                    continue
                for i in range(len(assign[name])):
                    for cand in (assign[name][i:i + 1] + assign[name][:i] + assign[name][i + 1:],
                                 assign[name][:i] + assign[name][i + 1:] + assign[name][i:i + 1]):
                        if cand != assign[name] and val(name, cand) - cur[name] > 1e-6:
                            assign[name] = cand
                            cur[name] = val(name, cand)
                            improved = done = True
                            break
                    if done:
                        break
            # swap servers between two names
            for i, x in enumerate(names):
                for y in names[i + 1:]:
                    if time.perf_counter() > deadline:
                        break
                    done = False
                    for ix, sx in enumerate(assign[x]):
                        for iy, sy in enumerate(assign[y]):
                            nx = list(assign[x])
                            ny = list(assign[y])
                            nx[ix], ny[iy] = sy, sx
                            delta = val(x, nx) + val(y, ny) - cur[x] - cur[y]
                            if delta > 1e-6:
                                assign[x], assign[y] = nx, ny
                                cur[x], cur[y] = val(x, nx), val(y, ny)
                                owner[sy[0]], owner[sx[0]] = x, y
                                improved = done = True
                                break
                        if done:
                            break
        return assign, sum(cur.values())

    best = None
    for start in starts:
        result = local({n: list(v) for n, v in start.items()})
        if best is None or result[1] > best[0] + 1e-6:
            best = (result[1], result[0])
    rng = random.Random(20261104)
    rounds = 0
    while time.perf_counter() < deadline and rounds < 60:
        rounds += 1
        order = list(pool)
        rng.shuffle(order)
        trial = {n: [] for n in names}
        for k, srv in enumerate(order):
            if k < len(names):
                trial[names[k]].append(srv)      # every name gets one first
            elif rng.random() < 0.7:
                trial[rng.choice(names)].append(srv)
        result = local(trial)
        if result[1] > best[0] + 1e-6:
            best = (result[1], result[0])
    return best



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
            ifaces = link.get("interfaces", [])
            starts_down = link.get("status") == "down"
            if starts_down or any(side in down_ifaces for side in ifaces):
                for other in ifaces:
                    if other.split("-")[0] != network_id:
                        down_hosts.add(other.split("-")[0])

        # Time intervals during which each host's link is down.
        down_intervals = {}
        for link in links:
            ifaces = link.get("interfaces", [])
            hosts_here = [i.split("-")[0] for i in ifaces
                          if i.split("-")[0] != network_id]
            changes = sorted(
                (e.get("time", 0), e.get("type") == "uplink")
                for e in events
                if e.get("type") in ("uplink", "downlink")
                and list(e.get("link", [])) == list(ifaces))
            is_up = link.get("status") != "down"
            start = None if is_up else 0
            for when, goes_up in changes:
                if goes_up and not is_up:
                    for h in hosts_here:
                        down_intervals.setdefault(h, []).append((start, when))
                    is_up, start = True, None
                elif not goes_up and is_up:
                    is_up, start = False, when
            if not is_up:
                for h in hosts_here:
                    down_intervals.setdefault(h, []).append((start, float("inf")))

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
                duration = 50  # the simulator's default session length

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
            end_time = request_time + duration
            if simulation_end is not None:
                end_time = min(end_time, simulation_end)
            entry.setdefault("detail", []).append(
                (request_time, end_time, needed))
            src_ip = event.get("src")
            entry.setdefault("model", []).append((
                request_time, end_time,
                max(1, int(needed)),
                (src_ip, event.get("src_port")),
                delays.get(src_ip, 0), event.get("dst")))

        # Peak number of servers needed at once per name (sweep line over
        # half-open [start, end) sessions; an end frees servers before a
        # start at the same instant takes them).
        for entry in requests.values():
            points = []
            for s0, e0, n in entry["detail"]:
                if e0 > s0:
                    points.append((s0, 1, n))
                    points.append((e0, 0, n))
            points.sort()
            load = peak = 0
            for _, is_start, n in points:
                load += n if is_start else -n
                peak = max(peak, load)
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

        # Refine the allocation (and the record TTL) against a model of the
        # revenue checker; the model only ever replaces the heuristic choice
        # when it predicts a strictly better outcome.
        total_sessions = sum(len(requests[n]["model"]) for n in requests)
        if records and len(candidates) > 1 and total_sessions <= 600:
            by_ip = {c["ip"]: (c["ip"], c["host"], c["delay"]) for c in candidates}
            names = sorted(records)
            start_assign = {n: [by_ip[r["ip"]] for r in records[n]] for n in names}
            sessions = {n: list(requests[n]["model"]) for n in names}
            all_delays = list(delays.values())
            avg = (2.0 * sum(all_delays) / len(all_delays)
                   if len(all_delays) >= 2 else 0)
            fail_times = [e.get("time", 0) for e in events
                          if e.get("type") == "allowserverfails"]
            fail_from = min(fail_times) if fail_times else None
            seen, uniq = set(), []
            for c in candidates:
                if c["ip"] not in seen:
                    seen.add(c["ip"])
                    uniq.append(by_ip[c["ip"]])
            # Alternative starting points for the search: the minimal one-server
            # allocation, and "each name takes the next best servers in turn".
            minimal = {n: [] for n in names}
            sequential = {n: [] for n in names}
            ranked = list(uniq)
            for n, srv in zip(sorted(names, key=lambda x: (-sum(
                    (b0 - a0) * l for a0, b0, l, _c, _d, _e in sessions[x]), x)), ranked):
                minimal[n].append(srv)
            left = list(ranked)
            for n in names:
                for _ in range(requests[n]["count"]):
                    if left:
                        sequential[n].append(left.pop(0))
            starts = [start_assign, minimal, sequential]
            best = None
            for ttl_try in (ttl_value, 3600 if ttl_value != 3600 else 50):
                model = _RevenueModel(avg, down_intervals, ttl_try, fail_from)
                score, trial = _improve_allocation(
                    names, sessions, starts, uniq, model, _SEARCH_SECONDS)
                if best is None or score > best[0] + 1e-6:
                    best = (score, ttl_try, trial)
            _score, ttl_value, final_assign = best
            records = {n: [{"ip": srv[0], "ttl": ttl_value} for srv in final_assign[n]]
                       for n in names if final_assign[n]}

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