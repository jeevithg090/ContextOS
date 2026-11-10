"""Known exfiltration-prone services and cloud metadata endpoints.

These services are legitimate tools, but each lets anyone create an endpoint and read whatever is
sent to it (request capture, public tunnels, paste/file drops, out-of-band interaction testing,
chat webhooks). That makes them the usual landing spot for data stolen through prompt injection.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from app.engines.trust.domains import host_within

REQUEST_CAPTURE = "request-capture service"
TUNNEL = "public tunnel service"
PASTE = "paste or anonymous file-sharing service"
OAST = "out-of-band interaction testing service"
CHAT_WEBHOOK = "chat webhook endpoint"
BOT_API = "messaging bot API"


# Why each category is risky, as a clause completing "<service> is a <category>: ...".
CATEGORY_RISK = {
    REQUEST_CAPTURE: "anyone can create an endpoint there and read every request sent to it",
    TUNNEL: "anyone can expose a server through it, so the receiver is whoever started the tunnel",
    PASTE: "anyone can upload data there and retrieve or share it anonymously",
    OAST: "it exists to receive callbacks for whoever generated the payload",
    CHAT_WEBHOOK: "whoever created the webhook reads everything posted to it",
    BOT_API: "whoever holds the bot token reads everything sent through it",
}


@dataclass(frozen=True)
class KnownService:
    name: str
    category: str
    domains: tuple[str, ...] = ()  # host equals or is a sub-domain of one of these
    labels: tuple[str, ...] = ()  # any non-suffix label of the host equals one of these
    path: re.Pattern[str] | None = None  # only when the URL path matches (e.g. Discord webhooks)
    canonical_suffix: str = ""  # appended to the canonical identifier when ``path`` matched

    @property
    def risk(self) -> str:
        return CATEGORY_RISK[self.category]


KNOWN_SERVICES: tuple[KnownService, ...] = (
    KnownService("Webhook.site", REQUEST_CAPTURE, domains=("webhook.site",)),
    KnownService("RequestBin", REQUEST_CAPTURE, labels=("requestbin",)),
    KnownService("Pipedream", REQUEST_CAPTURE, domains=("pipedream.net",)),
    KnownService("Beeceptor", REQUEST_CAPTURE, domains=("beeceptor.com",)),
    KnownService("Request Catcher", REQUEST_CAPTURE, domains=("requestcatcher.com",)),
    KnownService("Hookbin", REQUEST_CAPTURE, domains=("hookbin.com",)),
    KnownService("ngrok", TUNNEL, domains=("ngrok.io", "ngrok-free.app", "ngrok.app", "ngrok-free.dev", "ngrok.dev")),
    KnownService("Cloudflare quick tunnel", TUNNEL, domains=("trycloudflare.com",)),
    KnownService("localtunnel", TUNNEL, domains=("loca.lt", "localtunnel.me")),
    KnownService("Serveo", TUNNEL, domains=("serveo.net",)),
    KnownService("localhost.run", TUNNEL, domains=("lhr.life", "localhost.run")),
    KnownService("Pastebin", PASTE, domains=("pastebin.com",)),
    KnownService("paste.ee", PASTE, domains=("paste.ee",)),
    KnownService("Hastebin", PASTE, labels=("hastebin",)),
    KnownService("dpaste", PASTE, labels=("dpaste",)),
    KnownService("termbin", PASTE, domains=("termbin.com",)),
    KnownService("transfer.sh", PASTE, domains=("transfer.sh",)),
    KnownService("file.io", PASTE, domains=("file.io",)),
    KnownService("0x0.st", PASTE, domains=("0x0.st",)),
    KnownService("Interactsh", OAST, domains=("interact.sh",), labels=("oast",)),
    KnownService("Burp Collaborator", OAST, domains=("burpcollaborator.net", "oastify.com")),
    KnownService("DNSLog", OAST, domains=("dnslog.cn",)),
    KnownService(
        "Discord webhook",
        CHAT_WEBHOOK,
        domains=("discord.com", "discordapp.com"),
        path=re.compile(r"^/api(?:/v\d+)?/webhooks(?:/|$)", re.IGNORECASE),
        canonical_suffix="/api/webhooks",
    ),
    KnownService("Telegram Bot API", BOT_API, domains=("api.telegram.org",)),
)

# Instance metadata services hand out cloud credentials to whoever can reach them.
METADATA_IPS = frozenset(
    ipaddress.ip_address(a) for a in ("169.254.169.254", "169.254.170.2", "fd00:ec2::254", "100.100.100.200")
)
METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata.goog", "instance-data", "instance-data.ec2.internal"})


def match_service(host: str, path: str = "") -> KnownService | None:
    labels = host.split(".")[:-1]
    for service in KNOWN_SERVICES:
        hit = any(host_within(host, d) for d in service.domains) or any(lbl in service.labels for lbl in labels)
        if not hit:
            continue
        if service.path is not None and not service.path.match(path or ""):
            continue
        return service
    return None


def is_metadata_endpoint(host: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None) -> bool:
    return (ip is not None and ip in METADATA_IPS) or host in METADATA_HOSTS
