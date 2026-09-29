import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

USER_AGENT = "SentinelBridge/0.1 (+OSINT education project)"

# Small common-subdomain wordlist for the offline DNS brute-force fallback.
COMMON = [
    "www", "mail", "ftp", "api", "dev", "test", "staging", "admin", "portal",
    "app", "blog", "shop", "cdn", "static", "assets", "img", "media", "vpn",
    "intranet", "ns1", "ns2", "mx", "webmail", "autodiscover", "remote",
    "git", "jenkins", "ci", "dashboard", "status", "support", "help", "forum",
]


def _hackertarget(domain: str, timeout: int) -> list[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    resp = requests.get(url, timeout=timeout,
                        headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    names: set[str] = set()
    for line in resp.text.splitlines():
        host = line.split(",")[0].strip().lower()
        if host.endswith(domain) and host != domain and "." in host:
            names.add(host)
    return sorted(names)


def _crt_sh(domain: str, timeout: int) -> list[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    resp = requests.get(url, timeout=timeout,
                        headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    names: set[str] = set()
    for entry in resp.json():
        for name in entry.get("name_value", "").splitlines():
            cleaned = name.strip().lower().lstrip("*.")
            if cleaned.endswith(domain) and cleaned != domain:
                names.add(cleaned)
    return sorted(names)


def _google_ct(domain: str, timeout: int) -> list[str]:
    url = ("https://transparencyreport.google.com/transparencyreport/api/v3/"
           "httpsreport/ct/certsearch?includeExpired=true&includeSubdomains=true"
           f"&domain={domain}")
    resp = requests.get(url, timeout=timeout,
                        headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    names: set[str] = set()
    lines = resp.text.splitlines()
    for line in lines:
        if not line.startswith("5["):
            continue
        parts = line.split(",")
        for part in parts:
            host = part.strip().strip('"').strip()
            if host.endswith(domain) and host != domain and "." in host:
                names.add(host)
    return sorted(names)


def _dns_bruteforce(domain: str, timeout: int = 5, max_workers: int = 20) -> list[str]:
    """Offline fallback: try to resolve common subdomains directly via DNS.

    Requires no third-party API, so it works even when public CT sources are
    rate-limited or down.
    """
    def probe(sub):
        try:
            socket.gethostbyname(f"{sub}.{domain}")
            return sub
        except socket.gaierror:
            return None

    found: set[str] = set()
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for res in pool.map(probe, COMMON):
            if res:
                found.add(f"{res}.{domain}")
    return sorted(found)


def fetch_subdomains(domain: str, timeout: int = 25) -> list[str]:
    """Enumerate subdomains of a domain.

    Tries free Certificate Transparency / public-passive sources first:
    HackerTarget hostsearch, crt.sh, Google's Transparency Report API.
    Falls back to an offline DNS brute-force scan if they all fail or are
    rate-limited. Returns [] if nothing resolves.
    """
    domain = domain.strip().lower()
    for fetch in (_hackertarget, _crt_sh, _google_ct):
        try:
            found = fetch(domain, timeout)
            if found:
                return found
        except requests.RequestException:
            continue
    return _dns_bruteforce(domain)


def _resolve(hostname: str, timeout: int = 5):
    try:
        return hostname, socket.gethostbyname(hostname)
    except socket.gaierror:
        return hostname, None


def resolve_subdomains(subdomains: list[str], max_workers: int = 10) -> dict[str, str]:
    """Resolve a batch of hostnames to A records (only live hosts are returned)."""
    live: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_resolve, name) for name in subdomains]
        for future in as_completed(futures):
            hostname, ip = future.result()
            if ip:
                live[hostname] = ip
    return live