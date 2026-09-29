"""TLS certificate analytics — no external API, pure Python ssl + cryptography.

Returns subject/issuer/organization, validity window (with days-left warning),
Subject Alternative Names and signature/key strength (SHA-1 detection).
"""

import socket
import ssl
from collections.abc import Callable
from datetime import datetime

_STRIP = Callable[..., str | None]


def _decode(value: object) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode()
        except UnicodeDecodeError:
            return repr(value)
    return str(value)


def _keyed(parts: tuple) -> dict:
    return {k: _decode(v) for pair in parts for k, v in pair}


def get_cert_info(host: str, port: int = 443, timeout: float = 10.0) -> dict:
    """Fetch + parse the TLS certificate for host:port.

    Raises OSError/socket.timeout when the service is unreachable or not TLS.
    """
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ss:
            der = ss.getpeercert(True)
            info = ss.getpeercert()  # decoded dict

    subject = _keyed(info.get("subject", ())) or {}
    issuer = _keyed(info.get("issuer", ())) or {}

    san = []
    for kind, value in info.get("subjectAltName", []):
        if kind == "DNS":
            san.append(_decode(value))

    def _parse(raw: str) -> datetime | None:
        try:
            return datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            try:
                return datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=None)
            except ValueError:
                return None

    not_before = _parse(info.get("notBefore", ""))
    not_after = _parse(info.get("notAfter", ""))
    days_left = (not_after - datetime.utcnow()).days if not_after else None

    sig_alg = None
    key_bits = None
    sha1 = False
    try:
        from cryptography import x509  # installed alongside reportlab

        cert = x509.load_der_x509_certificate(der)
        sig_alg = getattr(cert.signature_algorithm_oid, "_name", None) or str(cert.signature_algorithm_oid)
        sha1 = "sha1" in sig_alg.lower()
        pub = cert.public_key()
        key_bits = int(getattr(pub, "key_size", 0) or 0)
    except Exception:  # noqa: BLE001
        pass

    serial = ""
    try:
        from cryptography import x509

        serial = format(x509.load_der_x509_certificate(der).serial_number, "x").upper()
    except Exception:  # noqa: BLE001
        serial = _decode(info.get("serialNumber", ""))

    return {
        "host": host,
        "subject_cn": subject.get("commonName") or subject.get("CN") or host,
        "subject_o": subject.get("organizationName") or subject.get("O") or "—",
        "issuer_cn": issuer.get("commonName") or issuer.get("CN") or "—",
        "issuer_o": issuer.get("organizationName") or issuer.get("O") or "—",
        "not_before": not_before.strftime("%Y-%m-%d") if not_before else "—",
        "not_after": not_after.strftime("%Y-%m-%d") if not_after else "—",
        "days_left": days_left,
        "expiring_soon": bool(days_left is not None and days_left <= 10),
        "expired": bool(days_left is not None and days_left < 0),
        "san": san[:20],
        "san_total": len(san),
        "serial": serial,
        "sig_alg": sig_alg or "unknown",
        "key_bits": key_bits,
        "sha1": sha1,
    }