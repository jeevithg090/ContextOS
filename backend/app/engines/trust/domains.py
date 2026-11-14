"""Host-name helpers: canonical hosts, IP literal parsing and registrable domains.

Pure and offline: nothing here resolves DNS or contacts a network.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

# Multi-label public suffixes (ICANN section, common subset) and private suffixes under which every
# sub-domain is controlled by a different party (so "alice.github.io" and "bob.github.io" are
# different registrable domains). A deliberately small, reviewed subset of the Public Suffix List.
PUBLIC_SUFFIXES: frozenset[str] = frozenset(
    {
        # United Kingdom
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "ltd.uk",
        "plc.uk",
        "me.uk",
        "net.uk",
        "nhs.uk",
        "sch.uk",
        # Australia / New Zealand
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "asn.au",
        "id.au",
        "co.nz",
        "org.nz",
        "net.nz",
        "govt.nz",
        "ac.nz",
        # Asia
        "co.jp",
        "ne.jp",
        "or.jp",
        "ac.jp",
        "go.jp",
        "gr.jp",
        "ad.jp",
        "co.kr",
        "or.kr",
        "ne.kr",
        "go.kr",
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "edu.cn",
        "com.hk",
        "org.hk",
        "net.hk",
        "edu.hk",
        "com.tw",
        "org.tw",
        "net.tw",
        "edu.tw",
        "com.sg",
        "org.sg",
        "net.sg",
        "edu.sg",
        "gov.sg",
        "co.in",
        "net.in",
        "org.in",
        "firm.in",
        "gen.in",
        "ind.in",
        "ac.in",
        "gov.in",
        "co.id",
        "or.id",
        "ac.id",
        "go.id",
        "com.my",
        "org.my",
        "net.my",
        "com.ph",
        "com.vn",
        "co.th",
        "in.th",
        "or.th",
        "ac.th",
        "co.il",
        "org.il",
        "ac.il",
        "gov.il",
        "com.tr",
        "org.tr",
        "net.tr",
        "gov.tr",
        # Americas
        "com.br",
        "net.br",
        "org.br",
        "gov.br",
        "edu.br",
        "com.mx",
        "org.mx",
        "gob.mx",
        "com.ar",
        "com.co",
        "com.pe",
        "com.ve",
        "com.uy",
        "com.ec",
        # Africa / Europe misc
        "co.za",
        "org.za",
        "gov.za",
        "ac.za",
        "com.ng",
        "co.ke",
        "com.eg",
        "com.pl",
        "com.ua",
        "co.at",
        "or.at",
        "com.es",
        "com.pt",
        "com.gr",
        "com.ru",
        # Private suffixes: hosting platforms where each sub-domain belongs to a different tenant
        "github.io",
        "githubusercontent.com",
        "gitlab.io",
        "pages.dev",
        "workers.dev",
        "vercel.app",
        "now.sh",
        "netlify.app",
        "herokuapp.com",
        "herokudns.com",
        "fly.dev",
        "onrender.com",
        "railway.app",
        "web.app",
        "firebaseapp.com",
        "appspot.com",
        "azurewebsites.net",
        "cloudapp.net",
        "azureedge.net",
        "blob.core.windows.net",
        "cloudfront.net",
        "s3.amazonaws.com",
        "elasticbeanstalk.com",
        "amplifyapp.com",
        "blogspot.com",
        "wordpress.com",
        "readthedocs.io",
        "surge.sh",
        "glitch.me",
        "repl.co",
        "replit.app",
        "replit.dev",
        "deno.dev",
        "ngrok.io",
        "ngrok-free.app",
        "ngrok.app",
        "ngrok-free.dev",
        "ngrok.dev",
        "trycloudflare.com",
        "loca.lt",
        "pipedream.net",
        "requestcatcher.com",
        "beeceptor.com",
        "interact.sh",
        "oastify.com",
        "burpcollaborator.net",
        "lhr.life",
        "serveo.net",
        "localtunnel.me",
    }
)

_IDEOGRAPHIC_DOTS = str.maketrans({"。": ".", "．": ".", "｡": "."})
_HOST_CHARS = re.compile(r"^[a-z0-9_.\-]+$")
_IPV4_PART = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")


@dataclass(frozen=True)
class HostInfo:
    """A canonical host plus what was learned while canonicalising it."""

    host: str  # lower-case, punycode, no trailing dot; IPv6 without brackets
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    ip_nonstandard: bool = False  # e.g. 2130706433 or 0x7f.1 instead of dotted decimal
    original: str = ""


def parse_ipv4_loose(text: str) -> ipaddress.IPv4Address | None:
    """Parse IPv4 the way ``inet_aton`` does: 1-4 parts, decimal, octal (0-prefix) or hex (0x).

    Browsers and HTTP libraries accept these forms, so "http://2130706433/" reaches 127.0.0.1.
    """

    parts = text.split(".")
    if not 1 <= len(parts) <= 4 or any(not _IPV4_PART.match(p) for p in parts):
        return None
    values: list[int] = []
    for part in parts:
        try:
            if part.startswith("0x"):
                values.append(int(part[2:] or "0", 16))
            elif len(part) > 1 and part.startswith("0"):
                values.append(int(part, 8))
            else:
                values.append(int(part, 10))
        except ValueError:
            return None
    *head, last = values
    if any(v > 255 for v in head) or last >= 256 ** (4 - len(head)):
        return None
    number = 0
    for v in head:
        number = number * 256 + v
    number = number * 256 ** (4 - len(head)) + last
    return ipaddress.IPv4Address(number)


def parse_ip(text: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address | None, bool]:
    """Return (address, written_in_nonstandard_notation) or (None, False) when not an IP."""

    candidate = text.strip().strip("[]")
    if not candidate:
        return None, False
    if ":" in candidate:
        try:
            addr6 = ipaddress.IPv6Address(candidate.split("%", 1)[0])
        except ValueError:
            return None, False
        mapped = addr6.ipv4_mapped
        return (mapped if mapped is not None else addr6), False
    try:
        return ipaddress.IPv4Address(candidate), False
    except ValueError:
        pass
    loose = parse_ipv4_loose(candidate)
    if loose is not None:
        return loose, True
    return None, False


def _to_ascii_host(host: str) -> str:
    if host.isascii():
        return host
    labels = []
    for label in host.split("."):
        if label.isascii():
            labels.append(label)
            continue
        try:
            labels.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            labels.append(label)
    return ".".join(labels)


def canonical_host(raw: str) -> HostInfo | None:
    """Canonicalise a bare host (no scheme, path or port). Returns None if it is not a host."""

    original = raw
    text = unquote(raw).strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if not text:
        return None
    ip, nonstandard = parse_ip(text)
    if ip is not None:
        return HostInfo(host=ip.compressed, ip=ip, ip_nonstandard=nonstandard, original=original)
    text = unicodedata.normalize("NFKC", text).translate(_IDEOGRAPHIC_DOTS).lower().rstrip(".")
    text = _to_ascii_host(text)
    if not text or not _HOST_CHARS.match(text) or ".." in text or text.startswith((".", "-")):
        return None
    # A host that only *became* an IP after Unicode normalisation (e.g. full-width digits).
    ip, nonstandard = parse_ip(text)
    if ip is not None:
        return HostInfo(host=ip.compressed, ip=ip, ip_nonstandard=True, original=original)
    return HostInfo(host=text, original=original)


def split_host_port(netloc: str) -> tuple[str, int | None]:
    """Split "host:port" / "[v6]:port" (userinfo already removed). Invalid ports are dropped."""

    netloc = netloc.strip()
    if netloc.startswith("["):
        end = netloc.find("]")
        if end != -1:
            host, rest = netloc[: end + 1], netloc[end + 1 :]
            port = rest[1:] if rest.startswith(":") else ""
            return host, int(port) if port.isdigit() else None
    if netloc.count(":") == 1:
        host, port = netloc.split(":", 1)
        return host, int(port) if port.isdigit() else None
    return netloc, None


def is_ip(host: str) -> bool:
    return parse_ip(host)[0] is not None


def registrable_domain(host: str | None) -> str | None:
    """The domain an organisation can register ("eTLD+1"). IPs and single labels return themselves."""

    if not host:
        return None
    host = host.lower().rstrip(".")
    if is_ip(host) or "." not in host:
        return host
    labels = host.split(".")
    suffix_len = 1
    for i in range(len(labels)):
        if ".".join(labels[i:]) in PUBLIC_SUFFIXES:
            suffix_len = len(labels) - i
            break
    if len(labels) <= suffix_len:
        return host
    return ".".join(labels[-(suffix_len + 1) :])


def split_registrable(domain: str) -> tuple[str, str]:
    """("acme", "co.uk") for "acme.co.uk"; the name label and its public suffix."""

    label, _, suffix = domain.partition(".")
    return label, suffix


def to_unicode(host: str) -> str | None:
    """Display form of a punycode host, or None when it has no punycode labels."""

    if "xn--" not in host:
        return None
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
            except UnicodeError:
                return None
        else:
            labels.append(label)
    return ".".join(labels)


def host_within(host: str, domain: str) -> bool:
    """True when ``host`` equals ``domain`` or is a sub-domain of it."""

    return host == domain or host.endswith("." + domain)
