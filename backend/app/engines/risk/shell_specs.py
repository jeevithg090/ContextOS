"""Static knowledge about shell programs used by ``app.engines.risk.shell`` (pure data).

Each network program spec says which options take a value and what that value is:
``file`` options map to a role (``read`` | ``write`` | ``upload`` | ``key``), ``data`` options may
reference a file with ``@path`` (curl style), ``url``/``host`` options name a remote target,
``email`` options name recipients and ``exec`` options name a program to run on connection (the
classic reverse-shell pattern). ``positional`` selects how bare arguments are interpreted.
"""

from __future__ import annotations

from typing import Any

# Programs that only wrap another command.
WRAPPERS: dict[str, set[str]] = {
    "sudo": {"-u", "-g", "-p", "-U", "-C", "-h", "-r", "-t", "-D", "-T"},
    "doas": {"-u", "-C"},
    "nohup": set(),
    "time": {"-f", "-o"},
    "nice": {"-n"},
    "ionice": {"-c", "-n", "-p"},
    "exec": {"-a"},
    "command": set(),
    "builtin": set(),
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "stdbuf": {"-i", "-o", "-e"},
    "watch": {"-n", "-d", "--interval"},
    "strace": {"-e", "-o", "-p"},
    "chroot": set(),
    "su": set(),
}

XARGS_VALUE_OPTS = {"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a", "--max-args", "--max-procs", "--delimiter"}

SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "ash", "busybox", "csh", "tcsh"}

# Interpreters and the flags that introduce inline code.
INTERPRETERS: dict[str, set[str]] = {
    "python": {"-c"}, "python2": {"-c"}, "python3": {"-c"}, "pypy": {"-c"}, "pypy3": {"-c"},
    "node": {"-e", "--eval", "-p", "--print"}, "nodejs": {"-e", "--eval", "-p", "--print"},
    "deno": {"eval"}, "bun": {"-e", "--eval"},
    "ruby": {"-e"}, "perl": {"-e", "-E"}, "php": {"-r"},
    "powershell": {"-c", "-command"}, "pwsh": {"-c", "-command"},
}

ENV_DUMP_PROGRAMS = {"printenv"}

_CURL: dict[str, Any] = {
    "value": {"-H", "--header", "-u", "--user", "-X", "--request", "-A", "--user-agent", "-e", "--referer",
              "-m", "--max-time", "--connect-timeout", "-r", "--range", "--retry", "-w", "--write-out",
              "--oauth2-bearer", "-U", "--proxy-user", "--resolve", "--connect-to", "-b", "--cookie"},
    "file": {"-T": "upload", "--upload-file": "upload", "-o": "write", "--output": "write", "-K": "read",
             "--config": "read", "-E": "key", "--cert": "key", "--key": "key", "--cacert": "read",
             "-c": "write", "--cookie-jar": "write", "--netrc-file": "key", "-D": "write", "--dump-header": "write"},
    "data": {"-d", "--data", "--data-binary", "--data-ascii", "--data-urlencode", "-F", "--form", "--json"},
    "url": {"--url"},
    "host": {"-x", "--proxy", "--preproxy"},
    "positional": "url",
}

_WGET: dict[str, Any] = {
    "value": {"--header", "-U", "--user-agent", "--post-data", "--body-data", "--user", "--password",
              "--http-user", "--http-password", "-e", "--execute", "--method", "-t", "--tries", "-T",
              "--timeout", "--referer"},
    "file": {"-O": "write", "--output-document": "write", "--post-file": "upload", "--body-file": "upload",
             "-i": "read", "--input-file": "read", "-o": "write", "--output-file": "write", "-a": "write",
             "-P": "write", "--directory-prefix": "write", "--certificate": "key", "--private-key": "key"},
    "data": set(),
    "url": set(),
    "host": {"--proxy"},
    "positional": "url",
}

_SSH_VALUE = {"-p", "-o", "-l", "-L", "-R", "-D", "-b", "-c", "-E", "-e", "-I", "-m", "-O", "-Q", "-S",
              "-W", "-w", "-B", "-P"}

_NC: dict[str, Any] = {
    "value": {"-p", "-s", "-w", "-i", "-q", "-x", "-X", "-T", "-I", "-O", "-V", "--source", "--wait"},
    "exec": {"-e", "-c", "--exec", "--sh-exec", "--lua-exec"},
    "positional": "host_port",
}

_MAIL: dict[str, Any] = {
    "value": {"-s", "--subject", "-r", "-S", "-f"},
    "file": {"-a": "upload", "-A": "upload", "--attach": "upload"},
    "email": {"-c", "-b", "--cc", "--bcc"},
    "positional": "emails",
}

_HTTPIE: dict[str, Any] = {
    "value": {"-a", "--auth", "--session", "-A", "--auth-type", "--verify", "--timeout"},
    "file": {"-o": "write", "--output": "write", "--cert": "key", "--cert-key": "key"},
    "positional": "httpie",
}

_PWSH_WEB: dict[str, Any] = {
    "value": {"-method", "-headers", "-body", "-contenttype", "-useragent", "-credential", "-timeoutsec"},
    "file": {"-infile": "upload", "-outfile": "write", "-certificate": "key"},
    "url": {"-uri"},
    "host": {"-proxy"},
    "positional": "url",
    "case_insensitive": True,
}

NETWORK_SPECS: dict[str, dict[str, Any]] = {
    "curl": _CURL,
    "wget": _WGET,
    "wget2": _WGET,
    "ssh": {"value": _SSH_VALUE, "file": {"-i": "key", "-F": "read"}, "host": {"-J"}, "positional": "ssh"},
    "sftp": {"value": _SSH_VALUE, "file": {"-i": "key", "-F": "read", "-b": "read"}, "host": {"-J"},
             "positional": "remote_or_file"},
    "scp": {"value": {"-P", "-o", "-c", "-l", "-S"}, "file": {"-i": "key", "-F": "read"}, "host": {"-J"},
            "positional": "remote_or_file"},
    "rsync": {"value": {"-e", "--rsh", "--exclude", "--include", "--filter", "-f", "--port", "-T",
                        "--temp-dir", "--chmod", "--chown", "--timeout", "--bwlimit", "--log-file"},
              "file": {"--password-file": "key", "--files-from": "read", "--exclude-from": "read"},
              "positional": "remote_or_file"},
    "nc": _NC, "ncat": _NC, "netcat": _NC,
    "telnet": {"value": {"-l", "-n", "-e"}, "positional": "host_port"},
    "socat": {"value": {"-d", "-lf", "-T", "-b"}, "positional": "socat"},
    "ftp": {"value": {"-P"}, "positional": "host_or_url"},
    "tftp": {"value": {"-m", "-c"}, "positional": "host_or_url"},
    "lftp": {"value": {"-u", "-p", "-e", "-c"}, "file": {"-f": "read"}, "positional": "host_or_url"},
    "smbclient": {"value": {"-U", "-W", "-p", "-c", "-m"}, "file": {"-A": "key"}, "positional": "host_or_url"},
    "dig": {"value": {"-p", "-t", "-c", "-q", "-x", "-b"}, "file": {"-f": "read", "-k": "key"}, "positional": "dns"},
    "kdig": {"value": {"-p", "-t", "-c", "-q", "-x", "-b"}, "positional": "dns"},
    "drill": {"value": {"-p", "-t", "-c", "-k"}, "positional": "dns"},
    "nslookup": {"value": set(), "positional": "dns"},
    "host": {"value": {"-t", "-c", "-W", "-R", "-N", "-m"}, "positional": "dns"},
    "http": _HTTPIE, "https": _HTTPIE, "xh": _HTTPIE, "xhs": _HTTPIE,
    "aria2c": {"value": {"-d", "--dir", "-o", "--out", "--header", "-x", "-s"}, "file": {"-i": "read"},
               "positional": "url"},
    "mail": _MAIL, "mailx": _MAIL, "mutt": _MAIL, "sendmail": _MAIL, "msmtp": _MAIL,
    "openssl": {"value": {"-servername", "-cert", "-key", "-CAfile", "-in", "-out"}, "host": {"-connect"},
                "positional": "none", "only_with_host": True},
    "invoke-webrequest": _PWSH_WEB, "iwr": _PWSH_WEB, "invoke-restmethod": _PWSH_WEB, "irm": _PWSH_WEB,
}

# CLIs that always talk to a known remote API (identifier is a service name, not an observed host).
SERVICE_CLIS: dict[str, tuple[str, str]] = {
    "gh": ("domain", "github.com"),
    "aws": ("service", "aws"),
    "gcloud": ("service", "gcp"),
    "gsutil": ("service", "gcp"),
    "bq": ("service", "gcp"),
    "az": ("service", "azure"),
    "kubectl": ("service", "kubernetes-api"),
    "doctl": ("service", "digitalocean"),
    "flyctl": ("service", "fly.io"),
    "heroku": ("service", "heroku"),
    "vercel": ("service", "vercel"),
}

# (program, subcommand) pairs that publish local content to a registry.
PUBLISHERS: dict[tuple[str, str], tuple[str, str]] = {
    ("npm", "publish"): ("domain", "registry.npmjs.org"),
    ("yarn", "publish"): ("domain", "registry.yarnpkg.com"),
    ("pnpm", "publish"): ("domain", "registry.npmjs.org"),
    ("twine", "upload"): ("domain", "upload.pypi.org"),
    ("cargo", "publish"): ("domain", "crates.io"),
    ("gem", "push"): ("domain", "rubygems.org"),
    ("docker", "push"): ("domain", "docker.io"),
    ("podman", "push"): ("domain", "docker.io"),
}

SOCAT_CONNECT_TYPES = {
    "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "openssl", "ssl", "socks", "socks4", "socks4a", "socks5",
    "proxy", "sctp", "sctp4", "sctp6", "dccp",
}
SOCAT_FILE_TYPES = {"file", "open", "create", "gopen", "pipe"}

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

DESTRUCTIVE_RM_TARGETS = {"/", "/*", "~", "~/", "~/*", "$HOME", "${HOME}", "*", ".", "..", "/home", "/etc",
                          "/usr", "/var", "/boot", "/root", "/bin", "/lib"}
