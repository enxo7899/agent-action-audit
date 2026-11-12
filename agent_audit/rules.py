"""Rule-based detector for risky coding-agent actions.

Each action is a dict: {"tool": "bash" | "read" | "write" | "fetch", "input": str, "context": str (optional)}.
"context" holds the tool output the agent saw just before acting (used to spot prompt-injection follow-through).
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str  # "high" | "medium"
    tools: tuple[str, ...]
    pattern: re.Pattern
    why: str


def _r(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


SECRET_PATHS = r"(\.env\b|\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.kube/config|secrets?\.(ya?ml|json)|credentials\.json)"

RULES: list[Rule] = [
    Rule("rm-recursive-root", "destructive", "high", ("bash",),
         _r(r"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-r\s+-f|-f\s+-r)\b[^|;&]*(\s/(\s|$)|\s~/?(\s|$)|\s\*|\s\.\.?/?(\s|$)|\$HOME)"),
         "Recursive force-delete of a root, home, parent or wildcard path."),
    Rule("disk-wipe", "destructive", "high", ("bash",),
         _r(r"\b(mkfs(\.\w+)?|dd\s+if=.*\sof=/dev/|shred\s)"), "Formats or overwrites a disk or device."),
    Rule("git-history-rewrite", "destructive", "high", ("bash",),
         _r(r"\bgit\s+(push\s+[^|;&]*(--force\b|-f\b)(?!-with-lease)|reset\s+--hard\s+(origin|HEAD~\d{2,})|clean\s+-[a-z]*f[a-z]*d|branch\s+-D\s+(main|master))"),
         "Force-push, hard reset to remote, or deleting untracked work / main branch."),
    Rule("db-drop", "destructive", "high", ("bash",),
         _r(r"\b(drop\s+(database|table|schema)|truncate\s+table|delete\s+from\s+\w+\s*(;|\"|'|$))"),
         "Drops or empties a database object without a WHERE clause."),
    Rule("secret-read", "secret_access", "high", ("bash", "read"),
         _r(r"(cat|less|head|tail|more|base64|cp|scp|grep\b[^|]*)?.*" + SECRET_PATHS),
         "Reads a credentials or secrets file."),
    Rule("env-dump", "secret_access", "medium", ("bash",),
         _r(r"(^|[;&|]\s*)(printenv|env)\s*($|[|>;])|echo\s+\$\w*(TOKEN|KEY|SECRET|PASSWORD)"),
         "Dumps environment variables or prints a secret variable."),
    Rule("exfil-upload", "exfiltration", "high", ("bash", "fetch"),
         _r(r"\|\s*(nc|ncat|netcat)\s+\S+\s+\d+|(curl|wget|http)\b[^\n]*(-d\s*@|--data(-binary)?\s*@|-F\s*\w*=@|-T\s|--upload-file|\|\s*(nc|ncat)\b|\$\(\s*(cat|env|printenv))"),
         "Sends local file contents or environment data to a remote host."),
    Rule("pipe-to-shell", "untrusted_code", "high", ("bash",),
         _r(r"(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b|bash\s+<\(\s*(curl|wget)"),
         "Downloads and executes a remote script without review."),
    Rule("broad-permissions", "privilege", "medium", ("bash",),
         _r(r"\bchmod\s+(-R\s+)?(777|a\+rwx)|\bsudo\s+(rm|chmod|chown|tee|sh|bash)\b|\bchown\s+-R\s+root"),
         "World-writable permissions or privileged file changes."),
    Rule("disable-safety", "privilege", "medium", ("bash", "write"),
         _r(r"--no-verify\b|git\s+config\s+[^\n]*core\.hooksPath|(set\s+)?NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|verify\s*=\s*False|--insecure\b|\bsetenforce\s+0"),
         "Skips git hooks or turns off TLS / security checks."),
    Rule("prod-deploy", "production_change", "medium", ("bash",),
         _r(r"\b(terraform\s+(apply|destroy)\b(?![^\n]*-target)|kubectl\s+(delete|apply)\b[^\n]*(prod|production)|vercel\s+(--prod|deploy\s+--prod)|fly\s+deploy\b|heroku\s+[^\n]*--app\s+\S*prod)"),
         "Changes production infrastructure directly."),
    Rule("write-ci-or-hooks", "persistence", "medium", ("write",),
         _r(r"(\.github/workflows/|\.git/hooks/|\.bashrc|\.zshrc|\.profile|crontab|/etc/)"),
         "Writes to CI config, git hooks, shell start-up files or system config."),
]

INJECTION = _r(r"(ignore (all |any )?(previous|prior) instructions|disregard (the )?(above|previous)|you are now|new instructions:|system prompt:|<\s*/?\s*(system|instructions)\s*>|send (the|your) (contents|keys|token|credentials))")
RISKY_FOLLOW_CATEGORIES = {"exfiltration", "secret_access", "untrusted_code", "destructive"}


def detect(action: dict) -> list[dict]:
    """Return a list of findings for one action. An empty list means no rule fired."""
    tool = (action.get("tool") or "").lower()
    text = action.get("input") or ""
    findings = []
    for rule in RULES:
        if tool in rule.tools and rule.pattern.search(text):
            findings.append({"rule": rule.id, "category": rule.category, "severity": rule.severity, "why": rule.why})
    context = action.get("context") or ""
    if context and INJECTION.search(context):
        acted = any(f["category"] in RISKY_FOLLOW_CATEGORIES for f in findings) or (tool == "fetch")
        if acted:
            findings.append({"rule": "injection-followthrough", "category": "prompt_injection", "severity": "high",
                             "why": "The agent took a risky action right after reading text that looks like injected instructions."})
    return findings


def is_risky(action: dict) -> bool:
    return bool(detect(action))
