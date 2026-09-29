import os
import re
import shutil
import subprocess
import tempfile

BASE_PATTERNS = [
    (r"AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    (r"AWS Session Key", re.compile(r"ASIA[0-9A-Z]{16}")),
    (r"GitHub Personal Access Token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    (r"GitHub Fine-Grained Token", re.compile(r"github_pat_[0-9A-Za-z_]{22,}")),
    (r"GitLab Personal Access Token", re.compile(r"glpat-[0-9A-Za-z\-_]{20,}")),
    (r"Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    (r"OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    (r"Stripe Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    (r"Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    (r"Slack Webhook URL", re.compile(r"hooks\.slack\.com/services/[A-Z0-9]+")),
    (r"Discord Webhook URL", re.compile(r"discord(app)?\.com/api/webhooks/\d{17,19}/[0-9A-Za-z_\-]{30,68}")),
    (r"Telegram Bot Token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b")),
    (r"npm Registry Auth Token", re.compile(r"//registry\.npmjs\.org/:_authToken=[0-9a-fA-F]{36}")),
    (r"SendGrid API Key", re.compile(r"SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}")),
    (r"Twilio API Key", re.compile(r"\bAC[a-f0-9]{32}\b")),
    (r"HuggingFace Token", re.compile(r"hf_[A-Za-z0-9]{20,}")),
    (r"Azure Storage Key", re.compile(r"(?i)(DefaultEndpointsProtocol|AccountName|AccountKey)\s*[:=]\s*[^;\s]{20,}")),
    (r"JWT Token", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    (r"Private Key", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    (r"Groq API Key", re.compile(r"gsk_[A-Za-z0-9]{20,}")),
    (r"Gemini / Google AI Key", re.compile(r"AQ\.[A-Za-z0-9\-_]{20,}")),
    (r"Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}")),
    (r"Claude API Key", re.compile(r"sk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{20,}")),
    (r"Replicate API Token", re.compile(r"r8_[A-Za-z0-9]{20,}")),
    (r"Cohere API Key", re.compile(r"\bco-[A-Za-z0-9]{20,}\b")),
    (r"Generic Secret (quoted)", re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[\"'][0-9A-Za-z_\-]{16,}[\"']")),
    (r"Generic Secret (unquoted .env)", re.compile(r"(?i)^([A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD)[A-Z_]*)\s*=\s*[A-Za-z0-9\-_]{16,}\s*$", re.MULTILINE)),
]

ALL_PATTERNS = BASE_PATTERNS

SKIP_EXT = {".pyc", ".pyo", ".so", ".dll", ".exe", ".png", ".jpg", ".jpeg", ".gif",
            ".pdf", ".zip", ".gz", ".lock", ".min.js"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "env"}


def normalize_url(target: str) -> str:
    """Accept 'github.com/user/repo', 'git@github.com:user/repo.git' etc.

    Also returns github.com URLs relative to full URLs. Non-GitHub values are
    returned unchanged (assumed local folder).
    """
    value = (target or "").strip()
    if value.startswith("git@github.com:") or value.startswith("git@gitlab.com:"):
        host, repo = value.split(":", 1)
        return f"https://{host[4:]}/{repo}"
    lowered = value.lower().lstrip("/")
    for prefix in ("www.", "https://www.", "http://www.", "https://", "http://"):
        lowered = lowered[len(prefix):] if lowered.startswith(prefix) else lowered
    if lowered.startswith(("github.com/", "gitlab.com/")):
        return "https://" + lowered
    return value


def resolve_repo(target: str) -> tuple[str, bool]:
    """Resolve an input to a local folder; clones public GitHub/GitLab URLs.

    Returns (path, cloned). Full clone (history included) so git-history scans
    still find secrets that were committed and later deleted.
    Raises RuntimeError if a local path does not exist (so "0 findings"
    silence is never a misleading valid result).
    """
    value = normalize_url((target or "").strip().strip('"').strip("'"))
    if value.startswith(("https://github.com/", "https://gitlab.com/")):
        dest = tempfile.mkdtemp(prefix="sentinel_clone_")
        cmd = ["git", "clone", "--quiet", value, dest]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=300, errors="replace")
        except (OSError, subprocess.TimeoutExpired, ValueError):
            shutil.rmtree(dest, ignore_errors=True)
            raise RuntimeError("git clone failed or timed out")
        if proc.returncode != 0:
            shutil.rmtree(dest, ignore_errors=True)
            raise RuntimeError(proc.stderr.strip() or "git clone failed")
        return dest, True
    if not os.path.isdir(value):
        raise RuntimeError(f"Local path not found: {value}")
    return value, False


def scan_folder(path: str, max_file_kb: int = 512) -> list[dict]:
    """Heuristic scan of a local folder for commonly leaked secrets."""
    findings: list[dict] = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            if ext in SKIP_EXT:
                continue
            full = os.path.join(root, name)
            if os.path.getsize(full) > max_file_kb * 1024:
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                continue
            for label, pattern in ALL_PATTERNS:
                if pattern.search(content):
                    findings.append({"file": full, "type": label})
    return findings


def scan_git_history(repo_path: str, max_kb: int = 4096) -> list[dict]:
    """Scan git commit history (all branches) for secrets that were ever committed.

    Secrets often remain in old commits even after being "deleted" from the
    working tree — this is the classic gitleaks-style check.
    """
    findings: list[dict] = []
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        return findings

    cmd = ["git", "-C", repo_path, "log", "-p", "--all"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=120, errors="replace")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return findings
    if proc.returncode != 0:
        return findings

    text = proc.stdout[: max_kb * 1024]
    current_commit, current_file = "", ""
    seen: set[tuple] = set()
    for line in text.splitlines():
        if line.startswith("commit ") and " " in line:
            current_commit = line.split()[1][:12]
            current_file = ""
            continue
        if line.startswith("+++ b/") or line.startswith("--- a/"):
            current_file = line.split("/", 1)[-1] if "/" in line else line
            continue
        if not line.startswith("+"):
            continue
        stripped = line[1:]
        for label, pattern in ALL_PATTERNS:
            if pattern.search(stripped):
                key = (label, current_file, current_commit)
                if key not in seen:
                    seen.add(key)
                    findings.append({"type": label, "file": current_file,
                                     "commit": current_commit})
                break
    return findings