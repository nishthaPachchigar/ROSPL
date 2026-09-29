"""Persistent scan history (SQLite). Every completed job is stored here so
the dashboard can show "Past Scans", reopen old reports and draw trend charts.

DB file lives at the project root: sentinel_history.db
"""

import json
import os
import sqlite3
import threading
from datetime import date, datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "sentinel_history.db")
_lock = threading.Lock()


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _lock:
        conn = _conn()
        try:
            conn.execute("""CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created TEXT NOT NULL,
                module TEXT NOT NULL,
                target TEXT,
                live_hosts INTEGER DEFAULT 0,
                subdomains INTEGER DEFAULT 0,
                ports INTEGER DEFAULT 0,
                packages INTEGER DEFAULT 0,
                vulns INTEGER DEFAULT 0,
                secrets INTEGER DEFAULT 0,
                git_history INTEGER DEFAULT 0,
                data TEXT DEFAULT '{}'
            )""")
            conn.commit()
        finally:
            conn.close()


def save_scan(module: str, ctx: dict) -> int:
    """Persist a finished scan. Returns the new row id (or 0 on non-JSON data)."""
    live = len(ctx.get("live_hosts") or {})
    subs = len(ctx.get("subdomains") or {})
    ports = sum(len(v) for v in (ctx.get("ports") or {}).values())
    pkg_rows = ctx.get("pkg_rows") or ctx.get("inv_rows") or []
    pkgs = len(pkg_rows)
    vulns = sum(len(p.get("vulns") or []) for p in pkg_rows)
    secrets = len(ctx.get("secrets") or [])
    gith = len(ctx.get("git_history") or [])

    target = (ctx.get("audit_target") or ctx.get("domain")
              or ctx.get("software") or ctx.get("folder") or "—")

    safe = {}
    for key, value in ctx.items():
        if key == "job_id":
            continue
        try:
            json.dumps(value)
            safe[key] = value
        except (TypeError, ValueError):
            continue

    with _lock:
        conn = _conn()
        try:
            cur = conn.execute(
                "INSERT INTO scans (created,module,target,live_hosts,subdomains,ports,"
                "packages,vulns,secrets,git_history,data) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), module, str(target),
                 live, subs, ports, pkgs, vulns, secrets, gith, json.dumps(safe)))
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


def recent_scans(limit: int = 15) -> list[dict]:
    with _lock:
        conn = _conn()
        try:
            rows = conn.execute(
                "SELECT id, created, module, target, live_hosts, subdomains, ports,"
                " packages, vulns, secrets, git_history FROM scans"
                " ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def get_scan(scan_id: int) -> dict | None:
    with _lock:
        conn = _conn()
        try:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            d["data"] = json.loads(d["data"] or "{}")
            return d
        finally:
            conn.close()


def trend_series(days: int = 14) -> list[dict]:
    """Per-day aggregates (hosts/vulns/secrets/packages) for the last `days` days.

    Repeated scans of the same target on the same day count once (max per
    target-day), so "hosts online" reflects distinct hosts, not re-runs.
    """
    per_target: dict[tuple[str, str], list[int]] = {}
    with _lock:
        conn = _conn()
        try:
            rows = conn.execute(
                "SELECT created, target, COALESCE(live_hosts,0), COALESCE(subdomains,0),"
                " COALESCE(vulns,0), COALESCE(secrets,0), COALESCE(packages,0)"
                " FROM scans").fetchall()
        finally:
            conn.close()
    for r in rows:
        day, tgt = r[0][:10], r[1] or "—"
        key = (day, tgt)
        vals = [r[2], r[3], r[4], r[5], r[6]]
        if key not in per_target:
            per_target[key] = vals
        else:
            per_target[key] = [max(a, b) for a, b in zip(per_target[key], vals)]

    buckets: dict[str, list[int]] = {}
    for (day, _), vals in per_target.items():
        b = buckets.setdefault(day, [0, 0, 0, 0, 0])
        for i, v in enumerate(vals):
            b[i] += v

    today = date.today()
    out = []
    for offset in range(days - 1, -1, -1):
        day = today - timedelta(days=offset)
        key = day.isoformat()
        b = buckets.get(key, [0, 0, 0, 0, 0])
        out.append({"day": str(day.day), "dayf": day.strftime("%d %b"),
                    "hosts": b[0], "subs": b[1], "vulns": b[2],
                    "secrets": b[3], "packages": b[4]})
    return out