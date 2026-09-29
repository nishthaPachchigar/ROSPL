"""Builds a clickable node/edge graph from recon results (no JS libraries).

Layers:  domain -> subdomains -> IPs -> open ports.
Per host, at most MAX_PORTS_PER_HOST port nodes are drawn so the graph
stays readable on large scans; the full list stays in the sub node's meta.
"""

MAX_PORTS_PER_HOST = 4

PORTS_KNOWN = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 6379: "redis", 27017: "mongodb",
}


def _shorten(host: str, domain: str) -> str:
    if domain and host.endswith("." + domain):
        short = host[: -(len(domain) + 1)]
        return short if short else "."
    return host


def build_graph(domain: str, subdomains: dict, ports: dict, geo: dict) -> dict:
    """Return {"nodes": [...], "edges": [[from_id, to_id], ...], stats}.
    Nodes carry {id, kind, label, meta} for the info panel.
    """
    nodes: list[dict] = []
    edges: list[list[str]] = []
    by_id: dict[str, dict] = {}

    root_label = domain or "target"
    root = {"id": root_label, "kind": "domain", "label": root_label, "meta": {"Type": "Target domain"}}
    nodes.append(root)
    by_id[root_label] = root

    hosts = list(subdomains.keys())
    ip_used: set[str] = set()

    for host in hosts:
        short = _shorten(host, domain)
        hid = f"sub:{host}"
        node = {"id": hid, "kind": "sub", "label": short, "meta": {"Host": host}}
        nodes.append(node)
        by_id[hid] = node
        edges.append([root_label, hid])

        ip = (subdomains.get(host) or "").strip()
        if ip:
            iid = f"ip:{ip}"
            m = {"IP": ip}
            g = (geo.get(ip) or {}).get("location") or {}
            if g:
                m["Location"] = ", ".join(str(x) for x in (g.get("city"), g.get("country")) if x)
            if iid not in by_id:
                node2 = {"id": iid, "kind": "ip", "label": ip, "meta": m}
                nodes.append(node2)
                by_id[iid] = node2
                ip_used.add(ip)
            else:
                node2 = by_id[iid]
                if g and "Location" not in node2["meta"]:
                    loc = ", ".join(str(x) for x in (g.get("city"), g.get("country")) if x)
                    if loc:
                        node2["meta"]["Location"] = loc
            edges.append([hid, iid])

        port_nodes = []
        port_meta = []
        for entry in (ports.get(host) or []):
            port = entry["port"] if isinstance(entry, dict) else entry
            service = entry.get("service") if isinstance(entry, dict) else None
            if not service:
                service = PORTS_KNOWN.get(int(port)) or ("port " + str(port))
            port_meta.append((int(port), str(service)))
        port_meta.sort(key=lambda p: (0 if p[1].lower() in ("unknown", "port " + str(p[0])) else 1, p[0]))

        if port_meta:
            drawn = ", ".join(str(p) for p, _ in port_meta[:MAX_PORTS_PER_HOST])
            for port, service in port_meta[:MAX_PORTS_PER_HOST]:
                pid = f"port:{host}:{port}"
                pnode = {"id": pid, "kind": "port", "label": str(port),
                         "meta": {"Port": str(port), "Service": str(service)}}
                nodes.append(pnode)
                by_id[pid] = pnode
                edges.append([hid, pid])
            if len(port_meta) > MAX_PORTS_PER_HOST:
                rest = len(port_meta) - MAX_PORTS_PER_HOST
                extra = ", ".join(str(p) for p, _ in port_meta[MAX_PORTS_PER_HOST:])
                node["meta"]["Open ports"] = f"{drawn} (+{rest} more: {extra})"
            else:
                node["meta"]["Open ports"] = drawn

    return {"nodes": nodes, "edges": edges,
            "root": root_label,
            "stats": {"hosts": len(hosts), "ips": len(ip_used),
                      "ports": sum(min(len(v), MAX_PORTS_PER_HOST) for v in ports.values())}}