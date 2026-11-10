"""Client-side secret masking and sensitive-path recognition.

The authoritative detector runs on the server (``app.engines.redaction``); the SDK cannot import
it. This module is a deliberately conservative, high-confidence subset used where the client must
act on its own:

- RESTRICT ``redact_secrets``: mask secrets in tool arguments before the guarded call runs (the
  guard then asks the server to re-scan the masked arguments, see ``contextos.restrictions``).
- The offline spool: secrets are masked before an event is written to disk.
- ``contextos scan``: files at sensitive paths are not uploaded unless ``--force`` is given.

Masks look like ``[REDACTED:<type>]``. Raw secret values are never logged.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

MASK = "[REDACTED:{kind}]"

_B = r"(?<![A-Za-z0-9_\-])"
_E = r"(?![A-Za-z0-9_\-])"
_BA = r"(?<![A-Za-z0-9])"
_EA = r"(?![A-Za-z0-9])"

# (type, compiled regex, group to mask: 0 = whole match)
_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str], int | str], ...] = tuple(
    (kind, re.compile(pattern), group)
    for kind, pattern, group in (
        ("private_key", r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----[\s\S]{16,20000}?-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----", 0),
        ("aws_access_key", _BA + r"(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}" + _EA, 0),
        ("github_token", _B + r"gh[pousr]_[A-Za-z0-9]{36,251}" + _E, 0),
        ("github_token", _B + r"github_pat_[A-Za-z0-9_]{60,251}" + _E, 0),
        ("gitlab_token", _B + r"gl(?:pat|dt|rt|ptt|cbt|soat|ft|imt)-[A-Za-z0-9_\-]{20,64}" + _E, 0),
        ("slack_token", _BA + r"xox[abprse]-[0-9A-Za-z][0-9A-Za-z\-]{8,250}[0-9A-Za-z]" + _EA, 0),
        ("stripe_key", _B + r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,247}" + _E, 0),
        ("stripe_webhook_secret", _B + r"whsec_[A-Za-z0-9+/=]{24,128}" + _E, 0),
        ("anthropic_api_key", _B + r"sk-ant-[A-Za-z0-9_\-]{20,}" + _E, 0),
        ("openai_api_key", _B + r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}" + _E, 0),
        ("openai_api_key", _B + r"sk-[A-Za-z0-9]{32,}" + _E, 0),
        ("google_api_key", _B + r"AIza[0-9A-Za-z_\-]{35}" + _E, 0),
        ("google_oauth_token", _B + r"ya29\.[0-9A-Za-z_\-]{20,}" + _E, 0),
        ("google_oauth_client_secret", _B + r"GOCSPX-[A-Za-z0-9_\-]{24,32}" + _E, 0),
        ("sendgrid_api_key", _B + r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}" + _E, 0),
        ("npm_token", _B + r"npm_[A-Za-z0-9]{36}" + _E, 0),
        ("huggingface_token", _B + r"hf_[A-Za-z0-9]{34,40}" + _E, 0),
        ("pypi_token", _B + r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}" + _E, 0),
        ("docker_hub_token", _B + r"dckr_pat_[A-Za-z0-9_\-]{27,}" + _E, 0),
        ("vault_token", _B + r"hv[sbr]\.[A-Za-z0-9_\-]{24,}" + _E, 0),
        ("contextos_api_key", _B + r"ctx[ks]_[A-Za-z0-9_\-]{20,}" + _E, 0),
        ("slack_webhook", r"(?i)https?://hooks\.slack\.com/(?P<body>(?:services|workflows|triggers)/[A-Za-z0-9_/\-]{20,})", "body"),
        ("discord_webhook", r"(?i)https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/(?P<body>\d{5,30}/[A-Za-z0-9_\-]{40,})", "body"),
        ("jwt", r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{16,}" + _E, 0),
        ("url_credentials", r"[A-Za-z][A-Za-z0-9+.\-]{1,24}://[^\s:/@'\"`<>\\]{0,128}:(?P<secret>[^\s@/'\"`<>\\]{3,256})@[A-Za-z0-9.\-_\[\]%]{1,253}", "secret"),
        ("bearer_token", r"(?i)\b(?:bearer|token|basic)\s+(?P<secret>[A-Za-z0-9\-._~+/]{16,4096}=*)(?![A-Za-z0-9\-._~+/=])", "secret"),
        ("azure_storage_key", r"(?i)AccountKey=(?P<secret>[A-Za-z0-9+/]{40,}={0,2})", "secret"),
        ("assigned_secret", r"(?i)\b[A-Za-z0-9_]*(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key|client[_\-]?secret)\b[\"']?\s*[:=]\s*[\"']?(?P<secret>[^\s\"',;`]{8,512})", "secret"),
    )
)

_PLACEHOLDER_RE = re.compile(r"^(?:\$\{?[A-Za-z_]|<[^>]*>$|\{\{|%\(|x{6,}$|\*{4,}|\[REDACTED)", re.IGNORECASE)

_SECRET_WORDS = ("password", "passwd", "passphrase", "secret", "token", "apikey", "accesskey", "privatekey",
                 "clientsecret", "authorization", "cookie", "credential", "credentials", "sessionkey", "bearer")
_METADATA_SUFFIXES = frozenset({
    "type", "kind", "id", "ids", "name", "count", "length", "len", "size", "prefix", "hint", "label",
    "fingerprint", "hash", "url", "uri", "path", "file", "filename", "env", "var", "expires", "expiry",
    "ttl", "version", "mode", "enabled", "required", "present", "status", "provider", "scope", "scopes",
    "limit", "max", "min", "timeout", "used", "usage", "budget", "redacted", "masked", "field",
})
_KEY_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")


def is_secret_key(key: str) -> bool:
    """True when a dict key / argument name typically holds a credential (``DB_PASSWORD``, ``apiKey``).

    Keys that merely describe a secret (``token_count``, ``secret_type``, ``api_key_id``) are not.
    """
    parts = [p.lower() for p in _KEY_SPLIT_RE.split(str(key)) if p]
    if not parts or parts[-1] in _METADATA_SUFFIXES:
        return False
    if parts[0] in {"is", "has", "num", "max", "min", "total", "use", "enable"}:
        return False
    joined = "".join(parts)
    return any(word in joined for word in _SECRET_WORDS) or parts[-1] in {"pwd", "pass", "auth"}


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.match(value.strip()))


def find_secrets(text: str) -> list[tuple[str, int, int]]:
    """``[(type, start, end), ...]`` for high-confidence secrets in ``text``, non-overlapping."""
    if not text:
        return []
    spans: list[tuple[str, int, int]] = []
    for kind, regex, group in _TOKEN_PATTERNS:
        for match in regex.finditer(text):
            start, end = match.span(group)
            if start < 0 or _is_placeholder(text[start:end]):
                continue
            spans.append((kind, start, end))
    spans.sort(key=lambda s: (s[1], -(s[2] - s[1])))
    merged: list[tuple[str, int, int]] = []
    for span in spans:
        if merged and span[1] < merged[-1][2]:
            continue
        merged.append(span)
    return merged


def mask_text(text: str) -> tuple[str, list[str]]:
    """Return ``(masked_text, [secret types found])``."""
    spans = find_secrets(text)
    if not spans:
        return text, []
    out: list[str] = []
    cursor = 0
    for kind, start, end in spans:
        out.append(text[cursor:start])
        out.append(MASK.format(kind=kind))
        cursor = end
    out.append(text[cursor:])
    return "".join(out), [kind for kind, _, _ in spans]


def mask_value(value: Any, *, _key: str | None = None, _depth: int = 0) -> tuple[Any, list[str]]:
    """Recursively mask secrets in str/dict/list/tuple values; values under secret-named keys are masked whole."""
    if _depth > 32:
        return "[REDACTED:depth_limit]", ["depth_limit"]
    if isinstance(value, str):
        if _key is not None and is_secret_key(_key) and value.strip() and not _is_placeholder(value):
            return MASK.format(kind="credential_field"), ["credential_field"]
        return mask_text(value)
    if isinstance(value, (bytes, bytearray)):
        return mask_value(bytes(value).decode("utf-8", errors="replace"), _key=_key, _depth=_depth)
    if isinstance(value, dict):
        found: list[str] = []
        out: dict[Any, Any] = {}
        for k, v in value.items():
            masked, kinds = mask_value(v, _key=str(k), _depth=_depth + 1)
            out[k] = masked
            found.extend(kinds)
        return out, found
    if isinstance(value, (list, tuple)):
        found = []
        items = []
        for item in value:
            masked, kinds = mask_value(item, _key=_key, _depth=_depth + 1)
            items.append(masked)
            found.extend(kinds)
        return (type(value)(items) if isinstance(value, tuple) else items), found
    if _key is not None and is_secret_key(_key) and isinstance(value, int) and not isinstance(value, bool):
        # Numeric PINs / OTPs under credential-named keys.
        return MASK.format(kind="credential_field"), ["credential_field"]
    return value, []


# --- sensitive paths -------------------------------------------------------------------------

_ENV_SAFE = frozenset({"example", "sample", "template", "dist", "defaults", "default", "schema", "tpl", "tmpl"})
_NAMED: dict[str, str] = {
    "id_rsa": "SSH private key", "id_dsa": "SSH private key", "id_ecdsa": "SSH private key",
    "id_ed25519": "SSH private key", ".netrc": "netrc file — plain-text machine logins",
    ".npmrc": "npm config — may contain registry tokens", ".pypirc": "PyPI upload credentials",
    ".git-credentials": "Git credential store — plain-text tokens", ".pgpass": "PostgreSQL password file",
    ".my.cnf": "MySQL client config — may contain a password", ".htpasswd": "HTTP basic-auth password file",
    ".vault-token": "HashiCorp Vault token", ".dockercfg": "Docker registry credentials",
    ".s3cfg": "s3cmd config — S3 access keys", ".boto": "Boto config — cloud credentials",
    ".bash_history": "Shell history — often contains pasted secrets",
    ".zsh_history": "Shell history — often contains pasted secrets",
    "credentials.tfrc.json": "Terraform Cloud credentials", "wallet.dat": "Cryptocurrency wallet",
}
_EXTENSIONS: dict[str, str] = {
    ".pem": "PEM file — private key or certificate material", ".key": "Private key file",
    ".p12": "PKCS#12 bundle — contains a private key", ".pfx": "PKCS#12 bundle — contains a private key",
    ".p8": "PKCS#8 private key", ".ppk": "PuTTY private key", ".jks": "Java keystore",
    ".keystore": "Keystore — private keys", ".kdbx": "KeePass password database",
    ".tfstate": "Terraform state — stores resource secrets in plain text",
    ".tfvars": "Terraform variables — often hold credentials", ".ovpn": "OpenVPN profile — embeds keys",
}
_NAME_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^(?:.*[._-])?secrets?\.(?:ya?ml|json|toml|ini|txt|env|properties)$"), "Secrets file"),
    (re.compile(r"^credentials?(?:\.(?:json|ya?ml|toml|xml|ini|txt|csv))?$"), "Credentials file"),
    (re.compile(r"^service[-_]?account.*\.json$"), "Cloud service-account key file"),
    (re.compile(r"^client[-_]?secrets?.*\.json$"), "OAuth client secret file"),
    (re.compile(r"^kubeconfig(?:[._-].*)?$|\.kubeconfig$"), "Kubernetes kubeconfig — cluster credentials"),
)
_DIRS: dict[str, str] = {
    ".ssh": "SSH directory — private keys and config", ".aws": "AWS CLI directory — access keys",
    ".gnupg": "GnuPG directory — private keys", "gcloud": "Google Cloud SDK credentials",
    ".azure": "Azure CLI cached tokens",
}
_SYSTEM = {"etc/shadow": "System password hashes", "etc/gshadow": "System group password hashes",
           "etc/sudoers": "sudo privilege configuration", "etc/master.passwd": "System password hashes"}


def _env_reason(name: str) -> str | None:
    if name in {".env", ".envrc"}:
        return f"{name} file — typically holds application secrets"
    if name.startswith(".env."):
        return None if set(name[5:].split(".")) & _ENV_SAFE else f"Environment file ({name}) — typically holds secrets"
    return None


def sensitive_path_reason(path: str) -> str | None:
    """Plain-language reason when ``path`` names a file that typically holds credentials, else ``None``."""
    if not path or len(path) > 4096:
        return None
    segments = [s for s in path.replace("\\", "/").lower().split("/") if s and s != "."]
    if not segments:
        return None
    name = segments[-1]
    checks: list[Callable[[], str | None]] = [
        lambda: _env_reason(name),
        lambda: next((reason for d, reason in _DIRS.items() if d in segments[:-1] or name == d), None),
        lambda: "Kubernetes kubeconfig — cluster credentials" if ".kube" in segments[:-1] and name == "config" else None,
        lambda: "Docker config — registry credentials" if ".docker" in segments[:-1] and name == "config.json" else None,
        lambda: _NAMED.get(name),
        lambda: _SYSTEM.get("/".join(segments[-2:])),
        lambda: next((reason for regex, reason in _NAME_PATTERNS if regex.search(name)), None),
        lambda: _EXTENSIONS.get(name[name.rfind("."):]) if name.rfind(".") > 0 else None,
    ]
    for check in checks:
        reason = check()
        if reason:
            return reason
    return None


__all__ = ["find_secrets", "is_secret_key", "mask_text", "mask_value", "sensitive_path_reason"]
