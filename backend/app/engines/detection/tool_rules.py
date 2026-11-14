"""Suspicious tool-request rules (ids prefixed TOOL-). Operate on normalised argument text plus the
structured resources a tool call touches. Works for Claude Code argument shapes (Bash {command},
Read {file_path}, WebFetch {url, prompt}, Write {file_path, content}) and generic dicts.

Category semantics (policies key on them, so each family keeps its own):

* ``TOOL-DESTRUCTIVE-*`` — irreversible damage (recursive deletes of root/home, disk writes, force
  pushes to main, dropped tables). Category ``suspicious_tool_use``; the rule-id prefix is the
  destructive signal the built-in "Deny destructive shell commands" policy matches.
* ``permission_escalation`` — the agent widening its own capabilities or control: agent/editor
  configuration writes, persistence, reverse shells. Matched by the built-in "Deny agent config
  tampering and privilege escalation" policy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.domain.enums import FindingCategory, Severity


@dataclass(frozen=True)
class ToolRule:
    rule_id: str
    category: str
    title: str
    severity: str
    confidence: float
    explanation: str
    pattern: re.Pattern[str]


def _rx(p: str) -> re.Pattern[str]:
    return re.compile(p, re.I)


# Known data-exfiltration / interaction services (raw-string patterns matched against hosts & args).
EXFIL_SERVICES = (
    "webhook.site",
    "requestbin",
    "requestb.in",
    "pipedream.net",
    "pipedream.com",
    "ngrok.io",
    "ngrok-free.app",
    "trycloudflare.com",
    "pastebin.com",
    "transfer.sh",
    "interact.sh",
    "oast.pro",
    "oast.site",
    "oast.fun",
    "oast.online",
    "burpcollaborator.net",
    "dnslog.cn",
    "beeceptor.com",
    "hookb.in",
    "0x0.st",
    "file.io",
    "gist.github.com",
    "paste.ee",
    "controlc.com",
    "hastebin.com",
    "glot.io",
)

# Agent / editor configuration files an attacker may try to overwrite for persistence.
AGENT_CONFIG_PATTERNS = (
    r"\.claude/settings[^/\s]*\.json",
    r"\.claude/",
    r"\.cursor/",
    r"\.cursorrules\b",
    r"\bAGENTS?\.md\b",
    r"\bCLAUDE\.md\b",
    r"\.mcp\.json\b",
    r"\.aider[^/\s]*\b",
    r"\.continue/",
    r"\.github/copilot",
    r"\.windsurfrules\b",
    r"\.codex/",
)

# Environment-variable names that usually hold credentials (matched case-insensitively). Ordinary
# variables (PATH, HOME, PWD, SHELL, NODE_ENV, GIT_AUTHOR_NAME, SSH_AUTH_SOCK …) do not match.
CREDENTIAL_VAR_NAME = (
    r"(?:[A-Z0-9_]*(?:KEY(?!BOARD|MAP)|TOKEN(?!IZER)|SECRET|PASSW(?:OR)?D|PASSPHRASE|CREDENTIAL|PRIVATE"
    r"|COOKIE|AUTHORIZATION|DSN|DATABASE_URL)[A-Z0-9_]*|[A-Z0-9_]*_PASS|MYSQL_PWD)"
)

TOOL_RULES: list[ToolRule] = [
    ToolRule(
        "TOOL-CRED-ENV",
        FindingCategory.CREDENTIAL_ACCESS,
        "Environment-variable dump",
        Severity.HIGH,
        0.8,
        "The command dumps environment variables, which routinely hold API keys, tokens and "
        "passwords. Printing them is a common first step in credential theft.",
        # ``env`` alone (or piped / redirected) dumps the environment; ``env VAR=1 cmd`` only sets it.
        # echo/printf count only for secret-looking variable names (``echo $PATH`` is routine).
        # process.env counts when the whole object reaches an output or transmit call.
        _rx(
            r"(?:^|[\n;&|]\s*)(?:printenv(?![\w.=/])|env(?=[ \t]*(?:$|[|>;&\n])))|\bcat\b[^|\n]{0,40}/proc/\d+/environ"
            r"|\b(?:echo|printf)\b[^|\n;&]{0,80}?\$\{?" + CREDENTIAL_VAR_NAME + r"\b"
            r"|\b(?:log|print|dump|send|post|stringify|write|upload|show|display)\b[^.\n;]{0,30}?\bprocess\.env\b(?!\s*(?:\.\s*\w|\[))"
        ),
    ),
    ToolRule(
        "TOOL-EXFIL-UPLOAD",
        FindingCategory.EXFILTRATION,
        "Outbound data upload",
        Severity.CRITICAL,
        0.86,
        "The command uploads local data to a remote server (curl/wget with a data-upload flag, or "
        "scp to a host). This is the outbound channel of a data-exfiltration attack.",
        _rx(
            r"\b(?:curl|wget)\b[^\n]*(?:-d\s*@|--data(?:-binary|-raw|-urlencode)?\s*@|-F\s+[\"']?\w+=@|--upload-file\b|-T\s+\S|--form\b[^\n]*@)|\bscp\b\s+\S+\s+\S+@|\brsync\b[^\n]*::?\S+@|\bcurl\b[^\n]*-X\s*(?:POST|PUT)[^\n]*-d\b"
        ),
    ),
    ToolRule(
        "TOOL-EXFIL-PIPE",
        FindingCategory.EXFILTRATION,
        "Pipe to network tool",
        Severity.CRITICAL,
        0.84,
        "Local data is piped into a network client (curl/wget/nc) — for example `base64 file | curl` — "
        "sending file or command output straight off the machine.",
        _rx(
            r"\|\s*(?:curl|wget|nc|ncat|netcat|socat)\b|\b(?:base64|cat|tar|gzip|xxd|openssl)\b[^|\n]*\|\s*(?:curl|wget|nc|ncat|netcat|socat)\b"
        ),
    ),
    ToolRule(
        "TOOL-REVSHELL",
        FindingCategory.PERMISSION_ESCALATION,
        "Reverse shell",
        Severity.CRITICAL,
        0.9,
        "The command opens a reverse shell, handing an attacker interactive control of the machine. "
        "There is no legitimate reason for an agent tool call to do this.",
        _rx(
            r"bash\s+-i\s*>?&?\s*/dev/tcp/|/dev/tcp/\d|\bnc\b[^\n]*\s-[a-z]*e\b|\bncat\b[^\n]*--exec\b|python[0-9.]*\s+-c\s+['\"][^'\"]*socket[^'\"]*(?:connect|SOCK_STREAM)|\bsocat\b[^\n]*exec|perl\s+-e[^\n]*socket|\bmkfifo\b[^\n]*\|\s*(?:nc|sh|bash)"
        ),
    ),
    ToolRule(
        "TOOL-DESTRUCTIVE-RM",
        FindingCategory.SUSPICIOUS_TOOL_USE,
        "Destructive recursive delete",
        Severity.CRITICAL,
        0.88,
        "The command recursively force-deletes a root, home, or wildcard path. One mistake or one "
        "injected instruction here can wipe the environment irreversibly.",
        _rx(
            r"\brm\b\s+(?:-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-[rf]\s+-[rf])[a-z]*\s+(?:/\s*$|/\s|~\s*/?\s*$|~/\s|/\*|\$HOME\b|--no-preserve-root)|\brm\b[^\n]*--no-preserve-root"
        ),
    ),
    ToolRule(
        "TOOL-DESTRUCTIVE-DISK",
        FindingCategory.SUSPICIOUS_TOOL_USE,
        "Destructive disk / device write",
        Severity.CRITICAL,
        0.88,
        "The command formats a filesystem or writes directly to a block device (mkfs, dd of=/dev). "
        "This destroys data at the device level.",
        _rx(r"\bmkfs(?:\.\w+)?\b|\bdd\b[^\n]*\bof=/dev/|>\s*/dev/sd[a-z]\b|\bshred\b[^\n]*/dev/|\bwipefs\b"),
    ),
    ToolRule(
        "TOOL-DESTRUCTIVE-PERM",
        FindingCategory.SUSPICIOUS_TOOL_USE,
        "Dangerous permission change",
        Severity.HIGH,
        0.82,
        "The command recursively makes files world-writable or changes ownership of a root/home tree, "
        "weakening the system's security posture broadly.",
        _rx(
            r"\bchmod\b\s+-[a-z]*R[a-z]*\s+(?:777|a\+rwx|0?777)\s+(?:/\s|/\*|~|\$HOME|/\S*)|\bchown\b\s+-[a-z]*R[a-z]*\s+\S+\s+(?:/\s|~\s|/\*)"
        ),
    ),
    ToolRule(
        "TOOL-DESTRUCTIVE-GIT",
        FindingCategory.SUSPICIOUS_TOOL_USE,
        "Force-push to protected branch",
        Severity.HIGH,
        0.78,
        "The command force-pushes to main/master, which can overwrite shared history and erase other "
        "people's work without recovery.",
        _rx(
            r"\bgit\b[^\n]*\bpush\b[^\n]*(?:--force\b|--force-with-lease\b|-f\b)[^\n]*\b(?:main|master|origin\s+(?:main|master))\b|\bgit\b[^\n]*\bpush\b[^\n]*\b(?:main|master)\b[^\n]*(?:--force\b|-f\b)"
        ),
    ),
    ToolRule(
        "TOOL-DESTRUCTIVE-DB",
        FindingCategory.SUSPICIOUS_TOOL_USE,
        "Destructive database statement",
        Severity.CRITICAL,
        0.85,
        "The command drops a database or table, or truncates/deletes without a filter — irreversible "
        "data loss.",
        _rx(
            r"\bDROP\s+(?:DATABASE|SCHEMA|TABLE)\b|\bTRUNCATE\s+(?:TABLE\s+)?\w+|\bDELETE\s+FROM\s+\w+\s*(?:;|$)(?![^\n]*\bWHERE\b)"
        ),
    ),
    ToolRule(
        "TOOL-PERSIST",
        FindingCategory.PERMISSION_ESCALATION,
        "Persistence mechanism",
        Severity.HIGH,
        0.8,
        "The command installs persistence (cron job, shell-rc edit, launch agent) so attacker code "
        "keeps running after the session ends.",
        _rx(
            r"\bcrontab\b|(?:\btee\b|>>?)\s*~?/?\.(?:bashrc|zshrc|bash_profile|profile|zprofile)\b|\blaunchctl\b\s+(?:load|bootstrap)|/Library/LaunchAgents/|/etc/cron|\bsystemctl\b[^\n]*\benable\b|\bschtasks\b[^\n]*/create"
        ),
    ),
    ToolRule(
        "TOOL-EXFIL-SERVICE",
        FindingCategory.EXFILTRATION,
        "Known exfiltration / interaction service",
        Severity.HIGH,
        0.82,
        "The destination is a public webhook, paste, or out-of-band interaction service commonly used "
        "to collect stolen data. Sending anything there should be treated as exfiltration.",
        _rx("|".join(re.escape(s) for s in EXFIL_SERVICES)),
    ),
    ToolRule(
        "TOOL-EXFIL-RAWIP",
        FindingCategory.EXFILTRATION,
        "Raw-IP destination",
        Severity.MEDIUM,
        0.68,
        "The destination is a bare IP address rather than a named host. Agents normally talk to named "
        "services; a raw IP is a frequent sign of an attacker-controlled drop point.",
        _rx(
            r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:[/?]|\b)|\b(?:nc|ncat|curl|wget|scp|ssh)\b[^\n]*(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"
        ),
    ),
    ToolRule(
        "TOOL-ENCODED-PAYLOAD",
        FindingCategory.SUSPICIOUS_TOOL_USE,
        "Obfuscated command execution",
        Severity.HIGH,
        0.76,
        "The command decodes a payload and pipes it straight into a shell (base64 | sh, eval of "
        "decoded text) — a technique used to hide what is actually being run.",
        _rx(
            r"\b(?:base64\s+(?:-d|--decode)|openssl\s+enc\s+-d|xxd\s+-r)\b[^\n]*\|\s*(?:sh|bash|zsh|python|perl|ruby|node)\b|\b(?:eval|exec)\b[^\n]*\$\((?:base64|printf|echo)[^)]*\|\s*base64|echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+(?:-d|--decode)"
        ),
    ),
    ToolRule(
        "TOOL-AGENT-CONFIG-WRITE",
        FindingCategory.PERMISSION_ESCALATION,
        "Write to agent/editor configuration",
        Severity.HIGH,
        0.8,
        "The call writes to an agent or editor configuration file (.claude/settings, .codex/, .cursor/, "
        "AGENTS.md, CLAUDE.md, .mcp.json). Editing these can silently grant new tools, switch off the "
        "agent's hooks or inject standing instructions into every future session.",
        _rx("|".join(AGENT_CONFIG_PATTERNS)),
    ),
]
