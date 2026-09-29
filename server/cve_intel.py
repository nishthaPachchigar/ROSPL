import requests

OSV_API = "https://api.osv.dev/v1"
EPSS_API = "https://api.first.org/data/v1/epss"
CISA_KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_TIMEOUT = 20
_HEADERS = {"User-Agent": "SentinelBridge/0.1 (+OSINT education project)"}


def _safe_json(url: str):
    resp = requests.get(url, timeout=_TIMEOUT, headers=_HEADERS)
    resp.raise_for_status()
    return resp.json()


def search_vulns(software: str, version: str = "", ecosystem: str = "") -> list[dict]:
    """Query OSV (free, no API key) for known vulnerabilities in a package."""
    query: dict = {"package": {"name": software}}
    if ecosystem:
        query["package"]["ecosystem"] = ecosystem
    if version:
        query["version"] = version
    resp = requests.post(f"{OSV_API}/query",
                         json=query, timeout=_TIMEOUT, headers=_HEADERS)
    resp.raise_for_status()
    return resp.json().get("vulns", [])


def cve_by_id(cve_id: str) -> dict:
    """Fetch details for a single CVE from OSV (national databases are mirrored)."""
    url = f"{OSV_API}/vulns/{cve_id.strip().upper()}"
    try:
        info = _safe_json(url)
    except requests.RequestException:
        return {
            "id": cve_id.strip().upper(),
            "summary": "",
            "severity": "unknown",
            "aliases": [],
            "published": "",
            "modified": "",
        }
    return {
        "id": cve_id.strip().upper(),
        "summary": info.get("summary", ""),
        "severity": _pick_severity(info),
        "aliases": info.get("aliases", []),
        "published": info.get("published", ""),
        "modified": info.get("modified", ""),
    }


def _pick_severity(info: dict) -> str:
    for s in info.get("database_specific", {}).get("severity", []):
        return s
    for ref in info.get("severity", []):
        return ref.get("score", "")
    return "unknown"


def epss_for_cve(cve_id: str) -> dict:
    """Fetch exploitation probability (EPSS) for a CVE - free FIRST.org API."""
    cve = cve_id.strip().upper()
    try:
        payload = _safe_json(f"{EPSS_API}?cve={cve}")
    except requests.RequestException:
        return {"cve": cve, "epss": None, "percentile": None}
    data = payload.get("data", [])
    if not data:
        return {"cve": cve, "epss": None, "percentile": None}
    try:
        return {
            "cve": cve,
            "epss": float(data[0]["epss"]),
            "percentile": float(data[0]["percentile"]),
        }
    except (KeyError, TypeError, ValueError):
        return {"cve": cve, "epss": None, "percentile": None}


def kev_for_cve(cve_id: str) -> bool:
    """Check whether a CVE is in CISA's Known Exploited Vulnerabilities list."""
    cve = cve_id.strip().upper()
    try:
        feed = _safe_json(CISA_KEV_FEED)
    except requests.RequestException:
        return False
    return any(item.get("cveID") == cve for item in feed.get("vulnerabilities", []))