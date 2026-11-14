"""Sensitive file-path recognition (``.env``, SSH keys, cloud CLI credentials, keystores, ...).

Paths are normalised first: quotes and ``file://`` stripped, Windows separators converted, home
directory spellings (``~``, ``$HOME``, ``%USERPROFILE%``, ``/Users/<name>``, ``/home/<name>``,
``C:\\Users\\<name>``) folded to ``~``, and matching is case-insensitive (Windows and default macOS
filesystems are). Reasons are plain-language explanations shown to users.
"""

from __future__ import annotations

import re
from functools import lru_cache

_HOME_RE = re.compile(
    r"^(?:\$HOME|\$\{HOME\}|%USERPROFILE%|%HOMEPATH%|~[A-Za-z0-9_.\-]*)(?=/|$)", re.IGNORECASE
)
_USER_DIR_RE = re.compile(r"^(?:[A-Za-z]:)?/(?:users|home)/[^/]+(?=/|$)|^/root(?=/|$)", re.IGNORECASE)

_ENV_SAFE_PARTS = frozenset(
    {"example", "sample", "template", "dist", "defaults", "default", "schema", "tpl", "tmpl", "skel", "stub"}
)
_SSH_KEY_NAMES = frozenset(
    {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk", "identity"}
)
_HISTORY_FILES = frozenset(
    {
        ".bash_history",
        ".zsh_history",
        ".sh_history",
        ".history",
        "fish_history",
        ".python_history",
        ".psql_history",
        ".mysql_history",
        ".node_repl_history",
        ".rediscli_history",
        ".sqlite_history",
    }
)

_NAMED_FILES: dict[str, str] = {
    ".npmrc": "npm config file — may contain registry auth tokens",
    ".yarnrc.yml": "Yarn config file — may contain registry auth tokens",
    ".pypirc": "PyPI config file — contains package upload credentials",
    ".netrc": "netrc file — stores machine logins and passwords in plain text",
    "_netrc": "netrc file — stores machine logins and passwords in plain text",
    ".git-credentials": "Git credential store — plain-text access tokens",
    ".pgpass": "PostgreSQL password file",
    ".my.cnf": "MySQL client config — may contain a password",
    ".htpasswd": "HTTP basic-auth password file (crackable hashes)",
    ".vault-token": "HashiCorp Vault token file",
    ".terraformrc": "Terraform CLI config — may contain registry tokens",
    "credentials.tfrc.json": "Terraform Cloud credentials",
    ".boto": "Boto config — may contain cloud credentials",
    ".s3cfg": "s3cmd config — contains S3 access keys",
    ".dockercfg": "Docker registry credentials",
    "settings-security.xml": "Maven master password file",
    "wallet.dat": "Cryptocurrency wallet",
    "login data": "Browser saved-password store",
    "login data for account": "Browser saved-password store",
    "web data": "Browser autofill store (may include payment data)",
    "cookies.sqlite": "Browser cookie store (session cookies)",
    "cookies.binarycookies": "Browser cookie store (session cookies)",
    "key3.db": "Firefox key store (decrypts saved passwords)",
    "key4.db": "Firefox key store (decrypts saved passwords)",
    "signons.sqlite": "Firefox saved-password store",
}

_EXTENSIONS: dict[str, str] = {
    ".pem": "PEM file — private key or certificate material",
    ".key": "Private key file",
    ".p12": "PKCS#12 bundle — contains a private key",
    ".pfx": "PKCS#12 bundle — contains a private key",
    ".p8": "PKCS#8 private key",
    ".ppk": "PuTTY private key",
    ".jks": "Java keystore — contains private keys",
    ".keystore": "Keystore — contains private keys",
    ".kdbx": "KeePass password database",
    ".kdb": "KeePass password database",
    ".keychain": "macOS keychain",
    ".keychain-db": "macOS keychain",
    ".ovpn": "OpenVPN profile — often embeds keys and certificates",
    ".tfstate": "Terraform state — stores resource secrets in plain text",
    ".tfvars": "Terraform variables — often hold credentials",
    ".wallet": "Cryptocurrency wallet",
}

_SYSTEM_FILES: dict[str, str] = {
    "etc/shadow": "System password hashes (/etc/shadow)",
    "etc/gshadow": "System group password hashes (/etc/gshadow)",
    "etc/master.passwd": "System password hashes (BSD master.passwd)",
    "etc/passwd": "System account database (/etc/passwd)",
    "etc/sudoers": "sudo privilege configuration",
    "security/opasswd": "Previous system password hashes",
    "config/sam": "Windows SAM registry hive — local password hashes",
}

_NAME_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^(?:.*[._-])?secrets?\.(?:ya?ml|json|toml|ini|txt|env|properties)$"), "Secrets file"),
    (re.compile(r"^credentials?\.(?:json|ya?ml|toml|xml|ini|txt|csv)$"), "Credentials file"),
    (re.compile(r"^service[-_]?account.*\.json$"), "Cloud service-account key file"),
    (re.compile(r"^client[-_]?secrets?.*\.json$"), "OAuth client secret file"),
    (re.compile(r"\.tfstate\.backup$"), "Terraform state backup — stores resource secrets in plain text"),
    (re.compile(r"^kubeconfig(?:[._-].*)?$|\.kubeconfig$"), "Kubernetes kubeconfig — cluster credentials"),
    (re.compile(r"^ssh_host_.*_key$"), "SSH host private key"),
)

# Files in ~/.ssh that are not private keys but still security-relevant. Public keys (``*.pub``) are
# not secrets and are handled before this table (``is_sensitive_path``).
_SSH_FILES: dict[str, str] = {
    "known_hosts": "SSH known_hosts — lists the servers this user connects to; changing it can enable interception",
    "authorized_keys": "SSH authorized_keys — controls who can log in; adding a key grants access",
    "authorized_keys2": "SSH authorized_keys — controls who can log in; adding a key grants access",
    "config": "SSH client config — hosts, users and the private keys used for them",
}

_BROWSER_HINTS = (
    "chrome",
    "chromium",
    "edge",
    "brave",
    "vivaldi",
    "opera",
    "firefox",
    "mozilla",
    "safari",
    "user data",
)


def _normalize(path: str) -> tuple[str, list[str]]:
    p = path.strip().strip("\"'`")
    if p.lower().startswith("file://"):
        p = p[7:]
    p = p.replace("\\", "/")
    p = _HOME_RE.sub("~", p)
    p = _USER_DIR_RE.sub("~", p)
    p = re.sub(r"/{2,}", "/", p)
    if len(p) > 1:
        p = p.rstrip("/")
    low = p.lower()
    segments = [s for s in low.split("/") if s and s != "."]
    return low, segments


def _env_reason(name: str) -> str | None:
    if name == ".env":
        return ".env file — typically holds application secrets"
    if name == ".envrc":
        return "direnv .envrc — commonly exports secrets into the shell"
    if name.startswith(".env."):
        parts = set(name[5:].split("."))
        return None if parts & _ENV_SAFE_PARTS else f"Environment file ({name}) — typically holds secrets"
    if name.endswith(".env") and len(name) > 4:
        stem_parts = set(name[:-4].replace("-", ".").replace("_", ".").split("."))
        return (
            None if stem_parts & _ENV_SAFE_PARTS else f"Environment file ({name}) — typically holds secrets"
        )
    return None


def _directory_reason(segments: list[str], name: str, low: str) -> str | None:
    dirs = segments[:-1]
    if name == ".ssh" or ".ssh" in dirs:
        return _SSH_FILES.get(name, "SSH directory — private keys and client configuration")
    if ".aws" in dirs:
        if name == "credentials":
            return "AWS credentials file — access keys in plain text"
        if name == "config":
            return "AWS CLI config — profiles, SSO and role settings"
        return "AWS CLI directory — cached credentials and SSO tokens"
    if "gcloud" in dirs:
        return "Google Cloud SDK directory — credentials and access tokens"
    if ".azure" in dirs:
        return "Azure CLI directory — cached access tokens"
    if ".kube" in dirs and name == "config":
        return "Kubernetes kubeconfig — cluster credentials"
    if ".docker" in dirs and name == "config.json":
        return "Docker config — registry credentials"
    if ("gh" in dirs or "hub" in dirs) and name in {"hosts.yml", "hub"} and ".config" in dirs:
        return "GitHub CLI token store"
    if ".cargo" in dirs and name in {"credentials", "credentials.toml"}:
        return "Cargo registry token"
    if ".gem" in dirs and name == "credentials":
        return "RubyGems API key"
    if "proc" in dirs and name == "environ":
        return "Process environment — may contain secrets"
    if ".electrum" in dirs or (".ethereum" in dirs and "keystore" in dirs):
        return "Cryptocurrency wallet keystore"
    if "keystore" in dirs and name.startswith("utc--"):
        return "Ethereum keystore file"
    if "solana" in dirs and name == "id.json":
        return "Solana keypair"
    if name in {"cookies", "local state"} and any(h in low for h in _BROWSER_HINTS):
        return (
            "Browser cookie/key store"
            if name == "cookies"
            else "Browser key store (decrypts saved passwords)"
        )
    if name == "logins.json" and ("firefox" in low or "mozilla" in low):
        return "Firefox saved-password store"
    return None


@lru_cache(maxsize=2048)
def is_sensitive_path(path: str) -> tuple[bool, str | None]:
    """``(True, reason)`` when ``path`` names a file that typically holds credentials or keys."""
    if not path or not isinstance(path, str) or len(path) > 4096:
        return False, None
    low, segments = _normalize(path)
    if not segments:
        return False, None
    name = segments[-1]
    if name.endswith(".pub") and len(name) > 4 and ".ssh" in segments[:-1] and "*" not in name:
        return False, None  # an SSH public key is meant to be shared; reading it exposes nothing secret

    for check in (_env_reason(name), _directory_reason(segments, name, low)):
        if check:
            return True, check
    if name in _SSH_KEY_NAMES:
        return True, "SSH private key"
    if name in _NAMED_FILES:
        return True, _NAMED_FILES[name]
    if name in _HISTORY_FILES:
        return True, "Shell history — commonly contains pasted secrets"
    tail = "/".join(segments[-2:])
    if tail in _SYSTEM_FILES:
        return True, _SYSTEM_FILES[tail]
    for regex, reason in _NAME_PATTERNS:
        if regex.search(name):
            return True, reason
    dot = name.rfind(".")
    if dot > 0 and name[dot:] in _EXTENSIONS:
        return True, _EXTENSIONS[name[dot:]]
    return False, None
