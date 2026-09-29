"""SentinelBridge — an open-source AI security reconnaissance assistant (MCP server).

Connect this server to any MCP-capable AI client (Claude Code, Cursor, OpenCode)
and ask things like:

    "Analyse example.com"
    "Scan example.com's attack surface"   (subdomains + open ports + locations)
    "Check the software inventory of this repo against OSV"
    "What do we know about CVE-2023-44487?"
    "Are there known vulns for nginx 1.18.0?"
    "Scan this folder for leaked secrets"

All data sources are free, open and require no API keys:
  - crt.sh / HackerTarget / Google CT  - subdomain enumeration
  - OSV (osv.dev)                       - vulnerability database (CVE mirror)
  - FIRST.org EPSS                      - exploitation probability
  - CISA KEV                            - known exploited vulnerabilities
  - ip-api.com                          - GeoIP (no key)
  - IANA RDAP                           - WHOIS domain registration (no key)
"""

from __future__ import annotations

from fastmcp import FastMCP

from server import (
    cve_by_id,
    epss_for_cve,
    kev_for_cve,
    search_vulns,
    fetch_subdomains,
    resolve_subdomains,
    build_markdown_report,
    build_pdf_report,
    build_sarif_report,
)
from server.geoip import geoip_batch, whois_rdap
from server.inventory import scan_software_inventory
from server.leaks import resolve_repo, scan_folder, scan_git_history
from server.ports import scan_hosts, scan_ports

mcp = FastMCP(
    "SentinelBridge",
    instructions=(
        "Security reconnaissance assistant. Tools cover subdomain enumeration, "
        "port scanning, GeoIP/WHOIS enrichment, CVE lookups (OSV/EPSS/CISA KEV), "
        "software inventory scans and leaked-secret scans. "
        "Use repeatedly on authorized targets only."
    ),
    version="2.0.0",
)


# ---------------------------------------------------------------------------
# Reconnaissance
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_domain(domain: str) -> dict:
    """Enumerate subdomains of a domain and resolve which hosts are live.

    Data source: Certificate Transparency logs via crt.sh (free, no key).
    """
    subs = fetch_subdomains(domain)
    live = resolve_subdomains(subs)
    return {
        "target": domain,
        "subdomain_count": len(subs),
        "live_hosts": live,
    }


@mcp.tool()
def scan_ports_on_hosts(hosts: list[str]) -> dict:
    """Probe a list of hostnames/IPs for 21 common open ports (SSH, HTTP,
    MySQL, Redis, RDP, ...). Flagged: database/remote-access ports.
    """
    results = scan_hosts(hosts)
    return {"host_count": len(hosts), "open_ports_by_host": results}


@mcp.tool()
def geoip_whois(domain: str) -> dict:
    """Enrich a target domain: GeoIP location/ISP for its resolved IPs
    (ip-api.com, free) and WHOIS registration info (IANA RDAP, free).
    """
    subs = fetch_subdomains(domain)
    live = resolve_subdomains(subs)
    ips = list({ip for ip in live.values() if ip})
    geo = geoip_batch(ips[:50])
    whois = whois_rdap(domain)
    return {
        "target": domain,
        "hosts_geoip": geo,
        "whois": whois,
    }


# ---------------------------------------------------------------------------
# Vulnerability intelligence
# ---------------------------------------------------------------------------

@mcp.tool()
def cve_lookup(cve_id: str) -> dict:
    """Fetch intelligence for a single CVE: description, severity,
    EPSS exploitation probability and CISA KEV (known-exploited) status.
    """
    records = cve_by_id(cve_id)
    epss = epss_for_cve(cve_id)
    kev = kev_for_cve(cve_id)
    return {
        "cve": records["id"],
        "summary": records["summary"],
        "severity": records["severity"],
        "published": records["published"],
        "epss": epss["epss"],
        "epss_percentile": epss["percentile"],
        "in_cisa_kev": kev,
    }


@mcp.tool()
def software_vulns(software: str, version: str = "") -> list[dict]:
    """Find known vulnerabilities for a software package (e.g. 'nginx' 1.18.0,
    'openssl'). Uses OSV - no API key required.
    """
    vulns = search_vulns(software, version)
    enriched = []
    for v in vulns[:10]:
        cve_id = (v.get("aliases") or [v.get("id")])[0]
        epss = epss_for_cve(cve_id)
        enriched.append({
            "id": v.get("id"),
            "aliases": v.get("aliases", []),
            "published": v.get("published", ""),
            "epss": epss["epss"],
            "in_cisa_kev": kev_for_cve(cve_id),
        })
    return enriched


@mcp.tool()
def software_inventory(code_dir: str) -> list[dict]:
    """Auto-detect the software packages of a project folder by parsing its
    manifest files (requirements.txt, package.json, go.mod, Cargo.toml,
    composer.json). Returns [(name, version)] for further OSV lookup.
    """
    return scan_software_inventory(code_dir)


# ---------------------------------------------------------------------------
# Leaked secrets
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_for_secrets(folder_path: str) -> dict:
    """Heuristically scan a folder or public GitHub/GitLab repo URL for leaked
    API keys, tokens and private keys (working tree + git history).
    Educational, regex-based detection.
    """
    path, cloned = resolve_repo(folder_path)
    try:
        findings = scan_folder(path)
        return {
            "folder": folder_path,
            "finding_count": len(findings),
            "findings": findings[:50],
        }
    finally:
        if cloned:
            import shutil
            shutil.rmtree(path, ignore_errors=True)


# ---------------------------------------------------------------------------
# Orchestrated audit + report
# ---------------------------------------------------------------------------

@mcp.tool()
def full_audit(target: str, packages: str = "", code_dir: str = "") -> dict:
    """Run a combined security audit on a target.

    - target:     domain to enumerate subdomains for
    - packages:   comma separated software list, e.g. "nginx 1.18.0, php 8.1"
    - code_dir:   optional local folder OR public GitHub/GitLab URL to auto-detect
                  software from + scan for secrets

    Returns a structured audit dict suitable for generate_report().
    """
    subs = fetch_subdomains(target)
    live = resolve_subdomains(subs)
    hosts = list(live.keys())[:10]
    ports = scan_hosts(hosts)
    ips = list({ip for ip in live.values() if ip})
    geo = geoip_batch(ips[:50])
    whois = whois_rdap(target)

    specs: list[tuple[str, str]] = []
    for spec in [p for p in packages.split(",") if p.strip()]:
        parts = spec.strip().split()
        specs.append((parts[0], parts[1] if len(parts) > 1 else ""))
    if code_dir:
        code_path, _cloned = resolve_repo(code_dir)
        try:
            for p in scan_software_inventory(code_path)[:20]:
                specs.append((p["name"], p["version"]))
        finally:
            if _cloned:
                import shutil
                shutil.rmtree(code_path, ignore_errors=True)
    specs = list(dict.fromkeys(specs))

    pkg_results = []
    for name, version in specs[:20]:
        vulns = []
        for v in search_vulns(name, version)[:10]:
            cve_id = (v.get("aliases") or [v.get("id")])[0]
            epss = epss_for_cve(cve_id)
            vulns.append({
                "id": cve_id,
                "epss": epss["epss"],
                "kev": kev_for_cve(cve_id),
                "severity": cve_by_id(cve_id)["severity"],
            })
        pkg_results.append({"name": name, "version": version, "vulns": vulns})

    leaks = []
    if code_dir:
        code_path, _cloned = resolve_repo(code_dir)
        try:
            leaks = scan_folder(code_path)
        finally:
            if _cloned:
                import shutil
                shutil.rmtree(code_path, ignore_errors=True)

    return {
        "target": target,
        "subdomains": live,
        "ports": ports,
        "geo": geo,
        "whois": whois,
        "packages": pkg_results,
        "leaks": leaks,
    }


@mcp.tool()
def generate_report(audit: dict, fmt: str = "markdown") -> str:
    """Convert a full_audit dict into a 'markdown', 'sarif' or 'pdf' report.
    PDF returns base64-encoded bytes (acceptable for client presentation);
    markdown/sarif return plain text.
    """
    if fmt == "sarif":
        return build_sarif_report(audit)
    if fmt == "pdf":
        import base64
        return base64.b64encode(build_pdf_report(audit)).decode()
    return build_markdown_report(audit)


if __name__ == "__main__":
    mcp.run(transport="stdio")