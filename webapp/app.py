"""SentinelBridge Web Dashboard.

Web UI around the same core engine the MCP server uses. Includes:
  - Full Audit (recon + ports + geoip/whois + software vulns + secrets)
  - Report generation + download (Markdown / SARIF / PDF)
  - Session activity log + live stats

Run:
    python webapp/app.py
    open http://127.0.0.1:5000
"""

from __future__ import annotations

import os
import shutil
import sys
import threading
import uuid
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, Response, redirect, render_template, request, session

from server.cve_intel import cve_by_id, epss_for_cve, kev_for_cve, search_vulns
from server.certs import get_cert_info
from server.geoip import geoip_batch, whois_rdap
from server.inventory import scan_software_inventory
from server.leaks import resolve_repo, scan_folder, scan_git_history
from server.ports import scan_hosts
from server.recon import fetch_subdomains, resolve_subdomains
from server.report import build_markdown_report, build_pdf_report, build_sarif_report

import webapp.db as store
import webapp.graph as graph

app = Flask(__name__)
app.secret_key = "sentinel-bridge-demo"

store.init_db()

# In-memory report store (PDF/audit too big for the session cookie).
REPORTS: dict[str, dict] = {}
# In-memory async audit jobs ({id: {"status","progress","stage",...}}).
JOBS: dict[str, dict] = {}

PORT_SCAN_LIMIT = 10  # hosts scanned per audit to keep it fast


def _job_update(job: dict, progress: int, stage: str, detail: str = "") -> None:
    """Safely update a background job's progress (called from the worker thread)."""
    if job.get("status") == "running":
        job["progress"] = progress
        job["stage"] = stage
        job["detail"] = detail


def _audit_one(domain: str, packages: str, code_dir: str,
               job: dict | None = None, p0: float = 0, p1: float = 100) -> dict:
    """Run every module against ONE target. Emits progress within [p0..p1].

    Returns the unified `audit` dict consumed by reports & templates.
    """
    def prog(frac: float) -> int:
        return int(p0 + (p1 - p0) * frac)

    specs: list[tuple[str, str]] = []
    if packages:
        for spec in [p for p in packages.split(",") if p.strip()]:
            parts = spec.strip().split()
            specs.append((parts[0], parts[1] if len(parts) > 1 else ""))
    specs = list(dict.fromkeys(specs))

    code_path = ""
    cloned = False
    if code_dir:
        if job:
            _job_update(job, prog(0.02), "Cloning repository", code_dir)
        code_path, cloned = resolve_repo(code_dir)
        if job:
            _job_update(job, prog(0.06), "Detecting software inventory")
        for p in scan_software_inventory(code_path)[:20]:
            specs.append((p["name"], p["version"]))
        specs = list(dict.fromkeys(specs))

    subs, live, ports, geo, whois = {}, {}, {}, {}, {}
    certs: list[dict] = []
    target = f"target: {code_dir}" if code_dir else f"packages: {packages}"

    if domain:
        if job:
            _job_update(job, prog(0.12), "Enumerating subdomains (CT logs)", domain)
        subs = fetch_subdomains(domain)
        if job:
            _job_update(job, prog(0.20), "Resolving live hosts")
        live = resolve_subdomains(subs)
        if job:
            _job_update(job, prog(0.28), "Scanning open ports")
        ports, geo = _enrich_hosts(live)
        try:
            certs = [get_cert_info(domain)]
        except Exception:  # noqa: BLE001
            certs = []
        if job:
            _job_update(job, prog(0.44), "WHOIS / RDAP registration")
        whois = whois_rdap(domain)
        target = domain

    if job:
        _job_update(job, prog(0.52), "Querying OSV / EPSS / CISA KEV", f"{len(specs)} packages")
    pkg_rows = []
    for idx, (name, ver) in enumerate(specs[:20]):
        if job:
            _job_update(job, prog(0.52 + 0.26 * (idx + 1) / max(1, len(specs[:20]))),
                        "Querying OSV / EPSS / CISA KEV", f"{name} {ver}")
        rows = []
        for v in search_vulns(name, ver)[:5]:
            cve_id = (v.get("aliases") or [v.get("id")])[0]
            epss = epss_for_cve(cve_id)
            rows.append({"id": cve_id, "epss": epss["epss"],
                         "kev": kev_for_cve(cve_id),
                         "severity": cve_by_id(cve_id)["severity"]})
        pkg_rows.append({"name": name, "version": ver, "vulns": rows})

    if job:
        _job_update(job, prog(0.80), "Scanning for leaked secrets")
    leaks = scan_folder(code_path) if code_path else []
    git_hist = scan_git_history(code_path) if code_path else []

    if cloned:
        shutil.rmtree(code_path, ignore_errors=True)

    return {"target": target, "all_subs": subs, "subdomains": live,
            "ports": ports, "geo": geo, "whois": whois, "certs": certs,
            "packages": pkg_rows, "leaks": leaks, "git_history": git_hist}


def run_audit(job_id: str, domain: str, packages: str, code_dir: str) -> None:
    """Background worker for the full audit. Writes progress + final context to JOBS."""
    job = JOBS[job_id]
    try:
        if not domain and not code_dir and not packages:
            raise ValueError("Enter at least a domain, packages, or a repo URL/folder to scan.")

        audit = _audit_one(domain, packages, code_dir, job=job, p0=5, p1=94)

        _job_update(job, 96, "Building reports")
        vuln_count = sum(len(p["vulns"]) for p in audit["packages"])
        summary = (f"{len(audit['subdomains'])} hosts · {vuln_count} vulns"
                   f" · {len(audit['leaks'])} secrets · {len(audit['git_history'])} history")

        rid = uuid.uuid4().hex[:8]
        REPORTS[rid] = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "target": audit["target"],
            "md": build_markdown_report(audit),
            "sarif": build_sarif_report(audit),
            "pdf": build_pdf_report(audit),
        }
        if len(REPORTS) > 20:
            REPORTS.pop(next(iter(REPORTS)))

        context = {
            "domain": domain,
            "packages": packages,
            "audit_target": audit["target"],
            "subdomains": audit["all_subs"],
            "live_hosts": audit["subdomains"],
            "ports": audit["ports"],
            "geo": audit["geo"],
            "whois": audit["whois"],
            "certs": audit["certs"],
            "pkg_rows": audit["packages"],
            "secrets": audit["leaks"],
            "git_history": audit["git_history"],
            "report_md": build_markdown_report(audit),
            "report_id": rid,
        }
        job["report_id"] = rid
        job["context"] = context
        job["activity_entry"] = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "module": "Full Audit",
            "detail": f"{audit['target']} → {summary}",
            "ok": True,
        }
        try:
            store.save_scan("Full Audit", context)
        except Exception:  # noqa: BLE001
            pass
        job["progress"] = 100
        job["stage"] = "Complete"
        job["status"] = "done"
    except Exception as exc:  # noqa: BLE001
        job["status"] = "error"
        job["error"] = str(exc)
        job["stage"] = "Failed"


def _log(module: str, detail: str, ok: bool = True) -> list[dict]:
    """Append an event to the per-session activity feed."""
    session.setdefault("activity", [])
    session["activity"].insert(0, {
        "time": datetime.now().strftime("%H:%M:%S"),
        "module": module,
        "detail": detail,
        "ok": ok,
    })
    session["activity"] = session["activity"][:25]
    return session["activity"]


def _enrich_hosts(subdomains: dict[str, str]) -> tuple[dict, dict, dict]:
    """Given host→ip, run port scan (capped), geoip and return (ports, geo)."""
    hosts = list(subdomains.keys())[:PORT_SCAN_LIMIT]
    ports = scan_hosts(hosts)
    all_ips = list({ip for ip in subdomains.values() if ip})
    geo = geoip_batch(all_ips[:50]) if all_ips else {}
    return ports, geo


def _start_module_job(module: str, form: dict[str, str]) -> str:
    """Create + launch a background job for one dashboard module."""
    job_id = uuid.uuid4().hex[:8]
    JOBS[job_id] = {"status": "running", "progress": 0, "stage": "Queued",
                    "detail": "", "module": module, "form": form,
                    "created": datetime.now().strftime("%H:%M:%S")}
    threading.Thread(target=_run_module_job, args=(job_id,), daemon=True).start()
    return job_id


def _run_module_job(job_id: str) -> None:
    job = JOBS[job_id]
    try:
        fn = MODULE_WORKERS[job["module"]]
        ctx, detail = fn(job)
        job["context"] = ctx
        job["activity_entry"] = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "module": MODULE_LABELS[job["module"]][0],
            "detail": detail,
            "ok": True,
        }
        try:
            store.save_scan(MODULE_LABELS[job["module"]][0], ctx)
        except Exception:  # noqa: BLE001
            pass
        job["progress"] = 100
        job["stage"] = "Complete"
        job["status"] = "done"
    except Exception as exc:  # noqa: BLE001
        job["status"] = "error"
        job["error"] = str(exc)
        job["stage"] = "Failed"


MODULE_LABELS = {
    "recon": ("Recon", "🔎 Running Domain Reconnaissance"),
    "cve": ("CVE", "🩺 Fetching CVE Intelligence"),
    "vulns": ("Software", "📦 Checking Software Vulnerabilities"),
    "secrets": ("Secrets", "🔑 Scanning for Leaked Secrets"),
    "inventory": ("Inventory", "🧰 Building Software Inventory"),
}


def _recon_job(job: dict) -> tuple[dict, str]:
    domain = job["form"].get("domain", "").strip().lower() or "wikipedia.org"
    _job_update(job, 30, "Enumerating subdomains (CT logs)", domain)
    subs = fetch_subdomains(domain)
    _job_update(job, 50, "Resolving live hosts")
    live = resolve_subdomains(subs)
    _job_update(job, 65, "Scanning ports + GeoIP lookup")
    ports, geo = _enrich_hosts(live)
    _job_update(job, 85, "WHOIS / RDAP registration")
    whois = whois_rdap(domain)
    _job_update(job, 92, "TLS certificate analysis")
    try:
        certs = [get_cert_info(domain)]
    except Exception:  # noqa: BLE001
        certs = []
    ctx = {"domain": domain, "subdomains": subs, "live_hosts": live,
           "ports": ports, "geo": geo, "whois": whois, "certs": certs}
    return ctx, f"{domain} → {len(live)}/{len(subs)} live"


def _cve_job(job: dict) -> tuple[dict, str]:
    cve_id = job["form"].get("cve_id", "").strip().upper() or "CVE-2023-44487"
    _job_update(job, 40, f"Looking up {cve_id}")
    rec = cve_by_id(cve_id)
    _job_update(job, 65, "Fetching EPSS exploitation score")
    epss = epss_for_cve(cve_id)
    _job_update(job, 85, "Checking CISA KEV status")
    kev = kev_for_cve(cve_id)
    ctx = {"cve_result": {"cve": rec["id"], "summary": rec["summary"],
                          "severity": rec["severity"], "published": rec["published"],
                          "epss": epss["epss"], "percentile": epss["percentile"],
                          "kev": kev}}
    return ctx, f"{cve_id} · EPSS {epss['epss']}"


def _vulns_job(job: dict) -> tuple[dict, str]:
    software = job["form"].get("software", "").strip().lower() or "nginx"
    version = job["form"].get("version", "").strip() or "1.18.0"
    _job_update(job, 35, "Querying OSV for known vulns", f"{software} {version}")
    rows = []
    for v in search_vulns(software, version)[:5]:
        cve_id = (v.get("aliases") or [v.get("id")])[0]
        epss = epss_for_cve(cve_id)
        rows.append({"id": v.get("id"), "aliases": v.get("aliases", []),
                     "published": v.get("published", "")[:10],
                     "epss": epss["epss"], "kev": kev_for_cve(cve_id)})
    ctx = {"vulns": rows, "software": f"{software} {version}"}
    return ctx, f"{software} {version} → {len(rows)} vulns"


def _secrets_job(job: dict) -> tuple[dict, str]:
    target = job["form"].get("folder", "").strip()
    if not target:
        target = os.path.join(os.path.dirname(__file__), "..", "demo", "leaky_app")
    _job_update(job, 20, "Preparing repository", target)
    path, cloned = resolve_repo(target)
    display = path if not cloned else target
    try:
        _job_update(job, 45, "Scanning working tree for secrets")
        findings = scan_folder(path)
        _job_update(job, 75, "Scanning git commit history")
        history = scan_git_history(path)
        ctx = {"secrets": findings, "git_history": history, "folder": display}
        return ctx, f"{len(findings)} tree + {len(history)} git history"
    finally:
        if cloned:
            shutil.rmtree(path, ignore_errors=True)


def _inventory_job(job: dict) -> tuple[dict, str]:
    target = job["form"].get("folder", "").strip()
    if not target:
        target = os.path.join(os.path.dirname(__file__), "..", "demo", "leaky_app")
    _job_update(job, 20, "Preparing repository", target)
    path, cloned = resolve_repo(target)
    display = path if not cloned else target
    try:
        _job_update(job, 40, "Detecting dependency files")
        found = scan_software_inventory(path)
        _job_update(job, 55, "Querying OSV / EPSS / CISA KEV", f"{len(found)} packages")
        packages = []
        for p in found[:30]:
            pkg_vulns = []
            for v in search_vulns(p["name"], p["version"])[:5]:
                cve_id = (v.get("aliases") or [v.get("id")])[0]
                epss = epss_for_cve(cve_id)
                pkg_vulns.append({"id": cve_id, "epss": epss["epss"],
                                  "kev": kev_for_cve(cve_id),
                                  "severity": cve_by_id(cve_id)["severity"]})
            packages.append({**p, "vulns": pkg_vulns})
        ctx = {"inv_folder": display, "inv_packages": found, "inv_rows": packages}
        return ctx, f"{len(found)} packages found"
    finally:
        if cloned:
            shutil.rmtree(path, ignore_errors=True)


MODULE_WORKERS = {
    "recon": _recon_job,
    "cve": _cve_job,
    "vulns": _vulns_job,
    "secrets": _secrets_job,
    "inventory": _inventory_job,
}


def _compare_audits(a: dict, b: dict) -> dict:
    """Build comparison rows + overlap lists for two audit dicts."""

    def flat_ports(ports: dict) -> set:
        out: set = set()
        for vals in ports.values():
            for v in vals:
                out.add(v["port"] if isinstance(v, dict) else int(v))
        return out

    def pkg_map(rows: list) -> dict:
        return {r["name"].lower(): r for r in rows}

    am, bm = pkg_map(a["packages"]), pkg_map(b["packages"])
    common = sorted(set(am) & set(bm))
    only_a = sorted(set(am) - set(bm))
    only_b = sorted(set(bm) - set(am))
    pa = flat_ports(a["ports"])
    pb = flat_ports(b["ports"])

    rows = [
        ("Subdomains", len(a["all_subs"]), len(b["all_subs"])),
        ("Live hosts", len(a["subdomains"]), len(b["subdomains"])),
        ("Open ports", len(pa), len(pb)),
        ("Packages", len(a["packages"]), len(b["packages"])),
        ("Known CVEs", sum(len(p["vulns"]) for p in a["packages"]),
         sum(len(p["vulns"]) for p in b["packages"])),
        ("Leaked secrets", len(a["leaks"]), len(b["leaks"])),
        ("Git history secrets", len(a["git_history"]), len(b["git_history"])),
    ]

    v_a = sum(len(p["vulns"]) for p in a["packages"])
    v_b = sum(len(p["vulns"]) for p in b["packages"])
    if v_a > v_b:
        summary = f"Target A is riskier: {v_a - v_b} more known CVEs and {len(a['leaks']) - len(b['leaks'])} more leaked secrets than Target B."
    elif v_b > v_a:
        summary = f"Target B is riskier: {v_b - v_a} more known CVEs and {len(b['leaks']) - len(a['leaks'])} more leaked secrets than Target A."
    else:
        summary = "Both targets scored the same on vulnerabilities — dig into the tables for details."

    return {"meta": [("Target A", a["target"]), ("Target B", b["target"])],
            "rows": rows, "summary": summary,
            "common_pkgs": [am.get(x, bm.get(x))["name"] for x in common],
            "only_a_pkgs": [am[x]["name"] for x in only_a],
            "only_b_pkgs": [bm[x]["name"] for x in only_b],
            "common_ports": sorted(int(p) for p in (pa & pb))}


def run_compare(job_id: str, target_a: dict, target_b: dict) -> None:
    job = JOBS[job_id]
    try:
        _job_update(job, 5, "Scanning Target A", target_a["label"])
        a = _audit_one(target_a["domain"], target_a["packages"], target_a["code_dir"],
                       job=job, p0=5, p1=50)
        _job_update(job, 55, "Scanning Target B", target_b["label"])
        b = _audit_one(target_b["domain"], target_b["packages"], target_b["code_dir"],
                       job=job, p0=55, p1=95)
        _job_update(job, 97, "Comparing results")
        cmp_data = _compare_audits(a, b)
        job["context"] = {"compare": cmp_data, "alabel": target_a["label"],
                          "blabel": target_b["label"]}
        job["activity_entry"] = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "module": "Compare",
            "detail": f"{a['target']} vs {b['target']}",
            "ok": True,
        }
        job["progress"] = 100
        job["stage"] = "Complete"
        job["status"] = "done"
    except Exception as exc:  # noqa: BLE001
        job["status"] = "error"
        job["error"] = str(exc)
        job["stage"] = "Failed"


@app.route("/", methods=["GET"])
def home():
    return render_template("landing.html")


@app.route("/dashboard", methods=["GET"])
def dashboard():
    try:
        history = store.recent_scans(15)
        trends = store.trend_series(14)
    except Exception:  # noqa: BLE001
        history, trends = [], []
    return render_template("index.html", activity=session.get("activity", []),
                           history=history, trends=trends)


@app.route("/recon", methods=["POST"])
def recon():
    job_id = _start_module_job("recon", {"domain": request.form.get("domain", "")})
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return {"job_id": job_id}
    return redirect(f"/scan/{job_id}")


@app.route("/cve", methods=["POST"])
def cve():
    job_id = _start_module_job("cve", {"cve_id": request.form.get("cve_id", "")})
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return {"job_id": job_id}
    return redirect(f"/scan/{job_id}")


@app.route("/vulns", methods=["POST"])
def vulns():
    form = {"software": request.form.get("software", ""),
            "version": request.form.get("version", "")}
    job_id = _start_module_job("vulns", form)
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return {"job_id": job_id}
    return redirect(f"/scan/{job_id}")


@app.route("/secrets", methods=["POST"])
def secrets():
    job_id = _start_module_job("secrets", {"folder": request.form.get("folder", "")})
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return {"job_id": job_id}
    return redirect(f"/scan/{job_id}")


@app.route("/inventory", methods=["POST"])
def inventory():
    job_id = _start_module_job("inventory", {"folder": request.form.get("folder", "")})
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return {"job_id": job_id}
    return redirect(f"/scan/{job_id}")


@app.route("/full", methods=["POST"])
def full():
    domain = request.form.get("domain", "").strip().lower()
    packages = request.form.get("packages", "").strip()
    code_dir = request.form.get("code_dir", "").strip()
    if not domain and not code_dir and not packages:
        log = _log("Full Audit", "no target given", ok=False)
        return render_template("index.html", activity=log,
                               error="Enter at least a domain, packages, or a repo URL/folder to scan.")
    job_id = uuid.uuid4().hex[:8]
    JOBS[job_id] = {"status": "running", "progress": 0, "stage": "Queued",
                    "detail": "", "created": datetime.now().strftime("%H:%M:%S")}
    threading.Thread(target=run_audit,
                     args=(job_id, domain, packages, code_dir),
                     daemon=True).start()
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return {"job_id": job_id}
    return redirect(f"/scan/{job_id}")


@app.route("/scan/<job_id>", methods=["GET"])
def scan_progress(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return "Scan job not found", 404
    return render_template("scan.html", job_id=job_id, job=job)


@app.route("/api/scan/<job_id>", methods=["GET"])
def scan_api(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return {"status": "not_found"}
    payload = {"status": job["status"], "progress": job.get("progress", 0),
               "stage": job.get("stage", ""), "detail": job.get("detail", "")}
    if job.get("status") == "error":
        payload["error"] = job.get("error", "Unknown error")
    if job.get("status") == "done":
        payload["report_id"] = job.get("report_id", "")
    return payload


@app.route("/results/<job_id>", methods=["GET"])
def scan_results(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return "Scan job not found", 404
    if job.get("compare"):
        if job.get("status") == "error":
            return render_template("compare_result.html",
                                   error=f"Compare failed: {job.get('error')}")
        if job.get("status") != "done":
            return redirect(f"/scan/{job_id}")
        ctx = dict(job.get("context", {}))
        ctx["activity"] = session.get("activity", [])
        return render_template("compare_result.html", **ctx)
    if job.get("status") == "error":
        module = MODULE_LABELS.get(job.get("module", ""), ("Full Audit", ""))[0]
        log = _log(module, f"failed: {job.get('error', '')[:60]}", ok=False)
        return render_template("index.html", activity=log,
                               error=f"{module} failed: {job.get('error')}")
    if job.get("status") != "done":
        return redirect(f"/scan/{job_id}")

    # activity log entry comes from the worker thread (sessions are request-scoped)
    session.setdefault("activity", [])
    entry = job.get("activity_entry")
    if entry and session["activity"][:1] != [entry]:
        session["activity"].insert(0, entry)
    session["activity"] = session["activity"][:25]

    ctx = dict(job.get("context", {}))
    ctx["job_id"] = job_id
    ctx["activity"] = session["activity"]
    return render_template("index.html", **ctx)


@app.route("/past/<int:scan_id>", methods=["GET"])
def past_scan(scan_id: int):
    row = store.get_scan(scan_id)
    if not row:
        return "Scan not found", 404
    ctx = dict(row["data"])
    if ctx.get("report_md"):
        ctx["report_id"] = f"past-{scan_id}"
    ctx["job_id"] = f"past-{scan_id}"
    ctx["scan_id"] = scan_id
    ctx["activity"] = session.get("activity", [])
    return render_template("index.html", **ctx)


@app.route("/graph/<ref>", methods=["GET"])
def network_graph(ref: str):
    ctx = None
    if ref.startswith("past-"):
        row = store.get_scan(int(ref[5:]))
        ctx = row["data"] if row else None
    else:
        job = JOBS.get(ref)
        if job and job.get("status") == "done" and not job.get("compare"):
            ctx = job.get("context", {})
    if not ctx:
        return "Graph not available for this scan", 404
    domain = ctx.get("domain") or ctx.get("audit_target", "").replace("target: ", "")
    g = graph.build_graph(domain, ctx.get("live_hosts") or {}, ctx.get("ports") or {},
                          ctx.get("geo") or {})
    if not g["nodes"]:
        return "No hosts to graph", 404
    return render_template("graph.html", g=g, title=domain,
                           activity=session.get("activity", []))


@app.route("/compare", methods=["GET"])
def compare_form():
    return render_template("compare.html", activity=session.get("activity", []))


@app.route("/compare", methods=["POST"])
def compare_run():
    def _pick(prefix: str) -> dict:
        return {"label": request.form.get(prefix + "_label", "").strip(),
                "domain": request.form.get(prefix + "_domain", "").strip().lower(),
                "packages": request.form.get(prefix + "_packages", "").strip(),
                "code_dir": request.form.get(prefix + "_code_dir", "").strip()}

    a, b = _pick("a"), _pick("b")
    a_label = a["label"] or a["domain"] or a["packages"] or a["code_dir"] or "Target A"
    b_label = b["label"] or b["domain"] or b["packages"] or b["code_dir"] or "Target B"
    a["label"], b["label"] = a_label, b_label
    if not (a["domain"] or a["packages"] or a["code_dir"]):
        return render_template("compare.html", error="Target A needs at least a domain, packages or a repo/folder.",
                               activity=session.get("activity", []))
    if not (b["domain"] or b["packages"] or b["code_dir"]):
        return render_template("compare.html", error="Target B needs at least a domain, packages or a repo/folder.",
                               activity=session.get("activity", []))
    job_id = uuid.uuid4().hex[:8]
    JOBS[job_id] = {"status": "running", "progress": 0, "stage": "Queued",
                    "detail": "", "compare": True,
                    "created": datetime.now().strftime("%H:%M:%S")}
    threading.Thread(target=run_compare, args=(job_id, a, b), daemon=True).start()
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return {"job_id": job_id}
    return redirect(f"/scan/{job_id}")


@app.route("/report/<rid>/<fmt>")
def report_download(rid: str, fmt: str):
    md, sarif, pdf = None, None, None
    target = ""
    if rid.startswith("past-"):
        row = store.get_scan(int(rid[5:]))
        if row:
            data = row["data"]
            audit = {"target": data.get("audit_target", row["target"]),
                     "subdomains": data.get("live_hosts") or {},
                     "ports": data.get("ports") or {},
                     "geo": data.get("geo") or {},
                     "whois": data.get("whois") or {},
                     "packages": data.get("pkg_rows") or [],
                     "leaks": data.get("secrets") or [],
                     "git_history": data.get("git_history") or []}
            try:
                md = build_markdown_report(audit)
                sarif = build_sarif_report(audit)
                pdf = build_pdf_report(audit)
                target = audit["target"]
            except Exception:  # noqa: BLE001
                md = sarif = pdf = None
    else:
        item = REPORTS.get(rid)
        if item:
            md, sarif, pdf = item["md"], item["sarif"], item["pdf"]
            target = item["target"]

    if not md:
        return Response("Report not found", status=404)
    if fmt == "sarif":
        data, mime, ext = sarif, "application/json", "sarif"
    elif fmt == "pdf":
        data, mime, ext = pdf, "application/pdf", "pdf"
    else:
        # UTF-8 BOM so Windows Notepad/Word opens it without mojibake.
        data = "\ufeff" + md
        mime, ext = "text/markdown; charset=utf-8", "md"
    filename = f"sentinel-{target}-{rid}.{ext}"
    return Response(data, mimetype=mime, headers={"Content-Disposition": f"attachment; filename={filename}"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)