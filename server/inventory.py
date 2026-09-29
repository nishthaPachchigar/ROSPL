import json
import os
import re


def _parse_requirements(path: str) -> list[tuple[str, str]]:
    """requirements.txt → [(name, version)]"""
    pkgs: list[tuple[str, str]] = []
    for raw in open(path, "r", encoding="utf-8", errors="ignore"):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:==|>=|<=|~=)\s*([0-9A-Za-z.\-]+)", line)
        if m:
            pkgs.append((m.group(1).lower(), m.group(2)))
    return pkgs


def _parse_package_json(path: str) -> list[tuple[str, str]]:
    """package.json → [(name, version)]"""
    pkgs: list[tuple[str, str]] = []
    try:
        data = json.load(open(path, "r", encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return pkgs
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, ver in (data.get(section) or {}).items():
            ver_clean = re.sub(r"^[\^~>=<]", "", str(ver))
            pkgs.append((name.lower(), ver_clean))
    return pkgs


def _parse_go_mod(path: str) -> list[tuple[str, str]]:
    """go.mod → [(module, version)]"""
    pkgs: list[tuple[str, str]] = []
    try:
        text = open(path, "r", encoding="utf-8", errors="ignore").read()
    except OSError:
        return pkgs
    for m in re.finditer(r"^\s*([\w./\-]+)\s+(\S+)\s*$", text, re.MULTILINE):
        name, ver = m.group(1), m.group(2)
        if name == "require" or "go " in ver:
            continue
        pkgs.append((name.lower(), ver))
    return pkgs


def _parse_cargo_toml(path: str) -> list[tuple[str, str]]:
    """Cargo.toml → [(name, version)]"""
    pkgs: list[tuple[str, str]] = []
    try:
        text = open(path, "r", encoding="utf-8", errors="ignore").read()
    except OSError:
        return pkgs
    for m in re.finditer(r'^([A-Za-z0-9_\-]+)\s*=\s*\{?\s*version\s*=\s*["\']([^"\']+)', text, re.MULTILINE):
        pkgs.append((m.group(1).lower(), m.group(2)))
    return pkgs


def _parse_composer_json(path: str) -> list[tuple[str, str]]:
    """composer.json → [(name, version)]"""
    pkgs: list[tuple[str, str]] = []
    try:
        data = json.load(open(path, "r", encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return pkgs
    for name, ver in (data.get("require") or {}).items():
        pkgs.append((name.lower(), re.sub(r"^[\^~>=<]", "", str(ver))))
    return pkgs


MANIFEST_PARSERS = [
    ("requirements.txt", _parse_requirements),
    ("package.json", _parse_package_json),
    ("go.mod", _parse_go_mod),
    ("Cargo.toml", _parse_cargo_toml),
    ("composer.json", _parse_composer_json),
]


def scan_software_inventory(code_dir: str) -> list[dict]:
    """Scan a project folder's manifest files and list (name, version) packages.

    Supports requirements.txt (PyPI), package.json (npm), go.mod (Go),
    Cargo.toml (Rust) and composer.json (PHP).
    """
    inventory: list[dict] = []
    seen: set[tuple[str, str]] = set()
    root = os.path.abspath(code_dir)
    for root_dir, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in
                   {".git", "__pycache__", "node_modules", ".venv", "venv", "env", "vendor", "dist", "build"}]
        for fname in files:
            parser = dict(MANIFEST_PARSERS).get(fname)
            if not parser:
                continue
            path = os.path.join(root_dir, fname)
            for name, ver in parser(path):
                key = (name, ver)
                if key not in seen:
                    seen.add(key)
                    inventory.append({"name": name, "version": ver,
                                      "source": os.path.relpath(path, root)})
    return inventory