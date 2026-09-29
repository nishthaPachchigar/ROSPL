import socket
from concurrent.futures import ThreadPoolExecutor

# (port, service) — the "doors" an attacker would probe first.
COMMON_PORTS = [
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (3000, "Dev/API"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (8080, "HTTP-alt"),
    (8443, "HTTPS-alt"),
    (9200, "Elasticsearch"),
    (27017, "MongoDB"),
]

# Ports whose exposure is especially dangerous (dashboards/RDP/DBs) — flagged.
SENSITIVE = {3306, 5432, 3389, 6379, 27017, 9200, 23, 445}


def _probe(host: str, port: int, timeout: float) -> int | None:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port
    except OSError:
        return None


def scan_ports(host: str, ports: list[int] | None = None, timeout: float = 0.8,
               max_workers: int = 25) -> list[dict]:
    """Check which of the common ports are open on a single host/IP."""
    services = dict(COMMON_PORTS)
    targets = ports or [p for p, _ in COMMON_PORTS]
    open_ports: list[dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for port in pool.map(lambda p: _probe(host, p, timeout), targets):
            if port is not None:
                open_ports.append({
                    "port": port,
                    "service": services.get(port, "unknown"),
                    "sensitive": port in SENSITIVE,
                })
    open_ports.sort(key=lambda x: x["port"])
    return open_ports


def scan_hosts(hosts: list[str], timeout: float = 0.8, max_workers: int = 12) -> dict[str, list[dict]]:
    """Scan a list of hostnames/IPs in parallel; returns {'host': [open ports]}."""
    results: dict[str, list[dict]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for host in hosts:
            results[host] = pool.submit(scan_ports, host, timeout=timeout).result()
    return results


def port_summary(open_ports: list[dict]) -> str:
    """Human summary like '22,80,443' or 'none'."""
    if not open_ports:
        return "none"
    return ",".join(str(p["port"]) for p in open_ports)