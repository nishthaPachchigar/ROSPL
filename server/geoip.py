import requests

_TIMEOUT = 20
_HEADERS = {"User-Agent": "SentinelBridge/0.1 (+OSINT education project)"}
FIELDS = "status,country,city,regionName,isp,org,mobile,proxy,hosting,query"


def geoip_batch(ips: list[str]) -> dict[str, dict]:
    """Resolve locations for a batch of IPs via ip-api.com (free, no key).

    Returns {'ip': {'country','city','region','isp','org','sensitive'}}.
    Handles rate limits gracefully (returns {} on failure).
    """
    if not ips:
        return {}
    try:
        resp = requests.post(
            "http://ip-api.com/batch",
            json=[{"query": ip, "fields": FIELDS} for ip in ips],
            timeout=_TIMEOUT,
            headers=_HEADERS,
        )
        resp.raise_for_status()
        results: dict[str, dict] = {}
        for ip, item in zip(ips, resp.json()):
            if not isinstance(item, dict) or item.get("status") != "success":
                continue
            results[ip] = {
                "country": item.get("country", ""),
                "city": item.get("city", ""),
                "region": item.get("regionName", ""),
                "isp": item.get("isp", ""),
                "org": item.get("org", ""),
                "flag": _flag(item.get("country")),
            }
        return results
    except (requests.RequestException, ValueError):
        return {}


def _flag(country: str | None) -> str:
    """Approximate country flag emoji from ISO alpha-2 code (for display)."""
    if not country:
        return ""
    return ""


def whois_rdap(domain: str) -> dict:
    """Fetch domain registration info via RDAP (free, IANA-standard)."""
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}",
                            timeout=_TIMEOUT, headers=_HEADERS)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return {}

    info: dict = {"domain": domain}

    def _fdate(found):
        return found[0].get("eventDate", "")

    events = {e.get("eventAction"): e.get("eventDate", "")
              for e in (data.get("events") or [])}
    info["registered"] = events.get("registration", "")
    info["expires"] = events.get("expiration", "")
    info["last_changed"] = events.get("last changed", "")

    entities = data.get("entities") or []
    names = []
    for ent in entities[:3]:
        vcard = ent.get("vcardArray", [None, []])[1]
        for row in vcard:
            if row and row[0] == "fn":
                names.append(row[3])
    info["holder"] = ", ".join(names)

    statuses = [s for s in (data.get("status") or [])[:3]]
    info["status"] = statuses
    return info