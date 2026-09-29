# SentinelBridge

> Open-source AI security reconnaissance assistant.
> Bolo ek domain — lega subdomains + open ports + locations + CVEs + leaked secrets, dega readable report.
> Built on the **Model Context Protocol (MCP)** — AI ka "USB port".

Do tarah se chala sakte ho: **MCP server** (kisi bhi AI client se) ya **Flask web dashboard** (browser se).

## Kya karta hai

| Command (AI ko) | Kya hota hai |
|---|---|
| `Analyse example.com` | Subdomain enumeration (crt.sh / HackerTarget / Google CT) + live host resolution |
| `Scan example.com's attack surface` | Upar wala + 21 common ports probe + GeoIP/WHOIS enrichment |
| `What about CVE-2023-44487?` | NVD/OSV summary + EPSS exploitation probability + CISA KEV status |
| `Known vulns for nginx 1.18.0?` | OSV vulnerability database lookup (no API key) |
| `Check the software inventory of this repo` | Auto-detect packages from requirements.txt / package.json / go.mod / Cargo.toml / composer.json |
| `Scan this folder for secrets` | Regex detection of leaked API keys / tokens / private keys (working tree + git history) |
| `Full audit example.com + packages + code dir` | Combined audit → Markdown / SARIF / PDF report |

## Web dashboard

Browser se koi bhi module alag se chala sakte ho, ya poora audit background me chalake progress bar dekh sakte ho.

| Page | Kya karta hai |
|---|---|
| `/dashboard` | Scan form + live activity feed + quick stats |
| `/recon` | Subdomain enumeration + live host resolution |
| `/cve` | Ek CVE ke liye NVD/OSV summary + EPSS + CISA KEV |
| `/vulns` | Software package ke known vulns (OSV se) |
| `/inventory` | Folder ka software inventory scan |
| `/secrets` | Folder ya public GitHub/GitLab repo ke leaked secrets |
| `/full` | Full audit — sab ek saath, live progress bar ke saath |
| `/graph/<ref>` | Clickable network graph: domain → subdomains → IPs → open ports |
| `/compare` | Do scans ka side-by-side diff |
| `/past/<id>` | Purani scans ka history (SQLite me store hota hai) |
| `/report/<id>/<fmt>` | Report download — `md`, `sarif` ya `pdf` |

## MCP tools (9)

`analyze_domain` · `scan_ports_on_hosts` · `geoip_whois` · `cve_lookup` · `software_vulns` ·
`software_inventory` · `scan_for_secrets` · `full_audit` · `generate_report`

> TLS certificate analytics (`server/certs.py`) aur network graph (`webapp/graph.py`)
> web dashboard me available hain — MCP tools nahi.

## Tech stack (100% free & open source)

- **MCP standard** `https://modelcontextprotocol.io` — open protocol
- **FastMCP** (Python SDK) — custom server
- **Flask** + **ReportLab** — web dashboard aur PDF reports
- Data sources (all free, no API keys): **crt.sh**, **HackerTarget**, **Google CT log**, **OSV (osv.dev)**, **FIRST.org EPSS**, **CISA KEV**, **ip-api.com** (GeoIP), **IANA RDAP** (WHOIS)
- Any MCP client: Claude Code, Cursor, OpenCode

## Setup

```bash
cd "D:\NISHTHA\SEM 7\ROSPL MINI PROJ"
pip install -r requirements.txt
```

## Chalao — option 1: web dashboard (sabse aasan)

```bash
python webapp/app.py
# browser me kholo: http://127.0.0.1:5000
```

Dashboard apne aap SQLite DB banata hai (`sentinel_history.db`, git-ignored hai) aur
har completed scan ka history store karta hai.

## Chalao — option 2: AI client se (recommended for MCP demo)

Add this MCP server to your AI client config:

**.mcp.json** (Claude Code):
```json
{
  "mcpServers": {
    "sentinel-bridge": {
      "command": "python",
      "args": ["-m", "server.main"],
      "cwd": "D:\\NISHTHA\\SEM 7\\ROSPL MINI PROJ"
    }
  }
}
```

**.opencode/opencode.json** (OpenCode):
```json
{
  "mcp": {
    "sentinel-bridge": {
      "command": "python",
      "args": ["-m", "server.main"],
      "cwd": "D:\\NISHTHA\\SEM 7\\ROSPL MINI PROJ"
    }
  }
}
```

Fir apne AI se pucho: *"Analyse wikipedia.org"*.

## Chalao — option 3: test / demo directly

```bash
python tests/smoke_test.py                        # list MCP tools
python -m server.main                             # raw stdio server (MCP client se connect karo)
python demo/run_demo.py wikipedia.org "nginx 1.18.0, php 8.1.0"
```

Demo real MCP protocol (stdio) se server ko drive karta hai — bilkul waise hi jaise
Claude Code / Cursor karte hain. Reports `demo/reports/` me likhi jati hain.

## Project structure

```
ROSPL MINI PROJ/
├── server/
│   ├── main.py        # MCP server entry — 9 tools
│   ├── recon.py       # subdomain enumeration + DNS resolve (3 free sources)
│   ├── ports.py       # 21 common port probe, database/remote ports flagged
│   ├── geoip.py       # ip-api.com GeoIP + IANA RDAP WHOIS
│   ├── cve_intel.py   # OSV / EPSS / CISA KEV lookups
│   ├── certs.py       # TLS cert analytics (subject, SANs, expiry, key strength)
│   ├── inventory.py   # software detection from 5 manifest formats
│   ├── leaks.py       # regex leaked-secret scanner + git history
│   └── report.py      # Markdown + SARIF + PDF report builder
├── webapp/
│   ├── app.py         # Flask dashboard — all routes, background audit jobs
│   ├── db.py          # SQLite scan history
│   ├── graph.py       # domain → subdomain → IP → port node/edge graph
│   └── templates/     # Jinja2 UI
├── demo/
│   ├── run_demo.py    # end-to-end MCP demo runner
│   ├── leaky_app/     # fake secrets — scanner demo ke liye
│   └── reports/       # generated sample reports
├── tests/smoke_test.py
└── requirements.txt
```

## Demo script (faculty ke liye)

1. `pip install -r requirements.txt`
2. `python webapp/app.py` → `http://127.0.0.1:5000` (ya AI client me MCP add karo — upar config)
3. Dashboard pe **Full Audit** chalao, ya AI se bolo:
   *"Full audit 'wikipedia.org' with packages nginx 1.18.0, and scan the demo/leaky_app folder for secrets"*
4. `generate_report` call karke **Markdown / SARIF / PDF** report download karo — pure 60 seconds, no manual tools

> ⚠️ Educational project — sirf authorized targets par chalao.
