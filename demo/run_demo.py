"""SentinelBridge demo runner.

Connects to the server over the REAL MCP protocol (stdio) and drives it
exactly like Claude Code / Cursor would:
  analyze_domain -> cve_lookup -> software_vulns -> full_audit -> generate_report

Run:
  python demo/run_demo.py [domain] [packages]
  python demo/run_demo.py wikipedia.org "nginx 1.18.0, php 8.1.0"

Reports are written to demo/reports/.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = os.path.dirname(os.path.abspath(__file__))
LEAKY_APP = os.path.join(HERE, "leaky_app")
REPORTS = os.path.join(HERE, "reports")


def _show(label: str, value) -> None:
    print(f"\n=== {label} ===")
    if isinstance(value, str):
        print(value)
    else:
        print(json.dumps(value, indent=2, default=str)[:2000])


async def main() -> None:
    domain = sys.argv[1] if len(sys.argv) > 1 else "wikipedia.org"
    packages = sys.argv[2] if len(sys.argv) > 2 else "nginx 1.18.0"

    params = StdioServerParameters(command="python", args=["-m", "server.main"],
                                   cwd=os.path.dirname(HERE))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. Recon
            subs = await session.call_tool(
                "analyze_domain", {"domain": domain})
            sub_data = json.loads(subs.content[0].text)
            _show(f"1. ANALYZE_DOMAIN({domain})", sub_data)

            # 2. CVE intel
            cve = await session.call_tool(
                "cve_lookup", {"cve_id": "CVE-2023-44487"})
            _show("2. CVE_LOOKUP(CVE-2023-44487)", json.loads(cve.content[0].text))

            # 3. Package vulnerabilities
            name, ver = packages.split()[0], packages.split()[1]
            vulns = await session.call_tool(
                "software_vulns", {"software": name, "version": ver})
            _show(f"3. SOFTWARE_VULNS({name} {ver})", json.loads(vulns.content[0].text))

            # 4. Leaked secrets
            secrets = await session.call_tool(
                "scan_for_secrets", {"folder_path": LEAKY_APP})
            _show(f"4. SCAN_FOR_SECRETS({LEAKY_APP})", json.loads(secrets.content[0].text))

            # 5. Combined audit
            audit = await session.call_tool(
                "full_audit",
                {"target": domain, "packages": packages, "code_dir": LEAKY_APP})
            audit_data = json.loads(audit.content[0].text)
            _show("5. FULL_AUDIT (combined)", audit_data)

            # 6. Reports
            aud_json = json.dumps(audit_data)
            report = await session.call_tool(
                "generate_report", {"audit": audit_data, "fmt": "markdown"})
            sarif = await session.call_tool(
                "generate_report", {"audit": audit_data, "fmt": "sarif"})

            os.makedirs(REPORTS, exist_ok=True)
            md_path = os.path.join(REPORTS, "sentinel_report.md")
            sarif_path = os.path.join(REPORTS, "sentinel_report.sarif")
            with open(md_path, "w", encoding="utf-8") as fh:
                fh.write(report.content[0].text)
            with open(sarif_path, "w", encoding="utf-8") as fh:
                fh.write(sarif.content[0].text)

            print("\n=== 6. REPORTS SAVED ===")
            print(f"  {md_path}")
            print(f"  {sarif_path}")
            print("\nDemo complete. Faculty ko yeh 2 files + console output dikhao.")


if __name__ == "__main__":
    asyncio.run(main())