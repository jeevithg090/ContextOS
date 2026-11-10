"""Destination assessment: where an agent is about to send data, and what we can say about it.

Every check is based on the destination's name or address only. Nothing here resolves DNS,
connects to the destination, or verifies who operates it or who will read the data, and the
reasons returned say so explicitly.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.domain.enums import TrustLevel
from app.engines.trust.canonical import (
    WEB_SCHEMES,
    canonical_email,
    canonical_url,
    has_scheme,
    looks_like_email,
    web_url_text,
)
from app.engines.trust.domains import (
    HostInfo,
    canonical_host,
    host_within,
    registrable_domain,
    split_host_port,
)
from app.engines.trust.domains import to_unicode as punycode_to_unicode
from app.engines.trust.lookalike import find_lookalike
from app.engines.trust.matching import (
    describe_rule,
    domain_candidates,
    identifier_candidates,
    matching_rules,
    normalise_pattern,
)
from app.engines.trust.services import is_metadata_endpoint, match_service
from app.engines.trust.specs import DestinationAssessment, DestinationHistory, TrustRuleSpec

DESTINATION_KINDS = frozenset({"domain", "ip", "email", "service", "agent", "unknown"})
ALLOW_LEVELS = frozenset({TrustLevel.TRUSTED.value, TrustLevel.APPROVED.value})
BLOCK_LEVELS = frozenset({TrustLevel.BLOCKED.value, TrustLevel.SUSPICIOUS.value})
_INTERNAL_SUFFIXES = (".internal", ".local", ".lan", ".corp", ".intranet", ".home.arpa")
_PUBLIC_NAME_RE = re.compile(r"\.[a-z][a-z0-9\-]*$|^localhost$")


@dataclass(frozen=True)
class DestinationTarget:
    kind: str
    canonical: str
    host: HostInfo | None = None
    path: str = ""  # URL path, used for service detection only (may contain tokens; never stored)


def _check(check: str, result: str, detail: str) -> dict[str, str]:
    return {"check": check, "result": result, "detail": detail}


def _host_target(raw: str, kind: str | None) -> DestinationTarget | None:
    raw = web_url_text(raw)
    if has_scheme(raw):
        parts = urlsplit(raw)
        if parts.scheme.lower() not in WEB_SCHEMES:
            return None
        host_text, _port = split_host_port(parts.netloc.rpartition("@")[2])
        path = parts.path
    else:
        first = re.split(r"[/?#]", raw, maxsplit=1)[0]
        if "@" in first:
            return None
        host_text, _port = split_host_port(first)
        path = urlsplit("//" + raw).path if "/" in raw else ""
    host = canonical_host(host_text)
    if host is None:
        return None
    if kind is not None and not has_scheme(raw) and host.ip is None and not _PUBLIC_NAME_RE.search(host.host):
        return None  # "slack" as a service name is a name, not a host
    service = match_service(host.host, path)
    canonical = host.host + (service.canonical_suffix if service and service.path is not None else "")
    resolved_kind = kind if kind == "service" else ("ip" if host.ip is not None else "domain")
    return DestinationTarget(kind=resolved_kind, canonical=canonical, host=host, path=path)


def parse_destination(kind: str, identifier: str) -> DestinationTarget:
    """Canonical destination: hosts (no port/path/credentials), lower-case emails, service names."""

    raw = (identifier or "").strip()
    k = (kind or "unknown").strip().lower()
    k = k if k in DESTINATION_KINDS else "unknown"
    if not raw:
        return DestinationTarget(kind=k, canonical="")
    if k == "agent":
        return DestinationTarget(kind="agent", canonical=" ".join(raw.split()))
    if k == "email" or (k == "unknown" and looks_like_email(raw)):
        email = canonical_email(raw)
        return DestinationTarget(kind="email", canonical=email.identifier, host=email.host)
    if k in ("domain", "ip", "unknown"):
        target = _host_target(raw, None if k != "unknown" else "unknown")
        if target is not None:
            return target
        return DestinationTarget(kind=k, canonical=raw.lower())
    # service
    target = _host_target(raw, "service")
    if target is not None:
        return target
    if has_scheme(raw):
        url = canonical_url(raw)
        if url is not None:
            scheme, _, rest = url.identifier.partition("://")
            netloc = re.split(r"[/?#]", rest, maxsplit=1)[0]
            return DestinationTarget(kind="service", canonical=f"{scheme}://{netloc}", host=url.host)
    return DestinationTarget(kind="service", canonical=" ".join(raw.lower().split()))


def allowlisted_domains(rules: Sequence[TrustRuleSpec]) -> set[str]:
    """Registrable domains named by enabled TRUSTED/APPROVED destination rules (no wildcards)."""

    domains: set[str] = set()
    for rule in rules:
        if not rule.enabled or rule.applies_to not in ("destination", "both") or rule.trust_level not in ALLOW_LEVELS:
            continue
        pattern = normalise_pattern(rule.pattern)
        if rule.match_field == "identifier":
            pattern = pattern.split("/", 1)[0].rpartition("@")[2]
        if pattern.startswith("*."):
            pattern = pattern[2:]
        if not pattern or any(ch in pattern for ch in "*?[]"):
            continue
        host = canonical_host(pattern)
        if host is None or host.ip is not None or "." not in host.host:
            continue
        reg = registrable_domain(host.host)
        if reg:
            domains.add(reg)
    return domains


def _address_checks(host: HostInfo, checks: list[dict[str, str]], signals: list[str]) -> bool:
    """IP literal / internal address / metadata checks. Returns True for loopback destinations."""

    ip = host.ip
    name = host.host
    loopback = False
    if ip is not None:
        if host.ip_nonstandard:
            checks.append(_check(
                "ip_literal", "fail",
                f"Written as '{host.original}', a non-standard form of the IP address {ip}; this notation is "
                "commonly used to slip past address filters.",
            ))
            signals.append(
                f"The address '{host.original}' is a disguised form of {ip}, a common way to evade address filters."
            )
        elif ip.is_loopback:
            checks.append(_check("ip_literal", "pass", f"Raw loopback address ({ip})."))
        else:
            checks.append(_check(
                "ip_literal", "warn",
                f"The destination is a raw IP address ({ip}), so domain-based allowlists and reputation do not apply.",
            ))
        if ip.is_loopback:
            loopback = True
            checks.append(_check("internal_address", "pass", "Loopback address: the data stays on this machine."))
        elif ip.is_unspecified:
            checks.append(_check(
                "internal_address", "warn", f"Unspecified address ({ip}); most systems route it to the local machine.",
            ))
        elif ip.is_link_local:
            checks.append(_check(
                "internal_address", "warn", "Link-local address: reachable only from the local network segment.",
            ))
        elif ip.is_private:
            checks.append(_check(
                "internal_address", "warn",
                "Private network address: internal to your network and not reachable from the internet.",
            ))
        elif ip.is_multicast or ip.is_reserved:
            checks.append(_check("internal_address", "warn", "Reserved or multicast address range."))
        else:
            checks.append(_check("internal_address", "pass", "Public internet address."))
    else:
        checks.append(_check("ip_literal", "pass", "Uses a host name, not a raw IP address."))
        if host_within(name, "localhost"):
            loopback = True
            checks.append(_check("internal_address", "pass", "'localhost' name: the data stays on this machine."))
        elif name.endswith(_INTERNAL_SUFFIXES) or "." not in name:
            checks.append(_check(
                "internal_address", "warn", f"'{name}' is an internal-only host name, not a public internet domain.",
            ))
    if ip is not None or "." not in name or name.endswith(_INTERNAL_SUFFIXES):
        if is_metadata_endpoint(name, ip):
            checks.append(_check(
                "cloud_metadata", "fail",
                "Cloud instance metadata endpoint: it hands out cloud credentials to anything that can reach it.",
            ))
            signals.append(
                f"{name} is a cloud instance metadata endpoint, which hands out cloud credentials to anything "
                "that can reach it."
            )
        else:
            checks.append(_check("cloud_metadata", "pass", "Not a known cloud instance metadata endpoint."))
    return loopback


def _name_checks(
    target: DestinationTarget, allowlisted: set[str], checks: list[dict[str, str]], signals: list[str]
) -> None:
    host = target.host
    if host is None:
        return
    service = match_service(host.host, target.path)
    if service is not None:
        checks.append(_check(
            "exfiltration_service", "fail",
            f"{service.name} is a {service.category}: {service.risk}.",
        ))
        signals.append(
            f"{target.canonical} belongs to {service.name}, a {service.category}: {service.risk}, which makes it "
            "a common exfiltration target."
        )
    else:
        checks.append(_check(
            "exfiltration_service", "pass", "Not a known request-capture, tunnel, paste or webhook service.",
        ))
    if host.ip is not None:
        return
    display = punycode_to_unicode(host.host)
    if display is not None:
        checks.append(_check(
            "punycode", "warn",
            f"Internationalised domain name, displayed as '{display}'. Such names can imitate other domains.",
        ))
    else:
        checks.append(_check("punycode", "pass", "Plain ASCII domain name (no punycode)."))
    if "." not in host.host:
        return
    reg = registrable_domain(host.host)
    if not allowlisted:
        checks.append(_check(
            "lookalike", "unknown",
            "No allowlisted destination domains are configured, so there was nothing to compare against.",
        ))
    elif reg in allowlisted:
        checks.append(_check("lookalike", "pass", f"'{reg}' is itself an allowlisted domain."))
    else:
        lookalike = find_lookalike(host.host, allowlisted)
        if lookalike is not None:
            checks.append(_check("lookalike", "fail", lookalike.detail))
            signals.append(f"{lookalike.detail} It may be impersonating an allowlisted destination.")
        else:
            count = len(allowlisted)
            noun = "domain" if count == 1 else "domains"
            checks.append(_check("lookalike", "pass", f"Does not resemble any of the {count} allowlisted {noun}."))


def _history_check(history: DestinationHistory | None) -> dict[str, str]:
    if history is None:
        return _check(
            "first_seen", "unknown",
            "No destination history was supplied, so whether data has been sent here before was not checked.",
        )
    if not history.previously_seen:
        return _check("first_seen", "warn", "First time this destination has been seen in this organisation.")
    plural = "transfer" if history.transfer_count == 1 else "transfers"
    return _check("first_seen", "pass", f"Seen before; {history.transfer_count} {plural} recorded.")


def _scope_reason(target: DestinationTarget) -> str:
    if target.kind == "email":
        return (
            "Only the address and its domain were checked; ContextOS did not verify that the mailbox exists "
            "or who will read the message."
        )
    if target.kind == "agent":
        return (
            "Agent destinations are identified by the name the integration reported; ContextOS did not verify "
            "the receiving agent's identity."
        )
    if target.host is not None:
        return (
            "These checks look only at the destination's address: ContextOS did not resolve DNS, connect to it, "
            "or verify who operates it or who will receive the data."
        )
    return (
        "Only the destination's name was checked against trust rules; ContextOS did not verify who operates it "
        "or who will receive the data."
    )


def assess_destination(
    kind: str,
    identifier: str,
    *,
    rules: Sequence[TrustRuleSpec],
    history: DestinationHistory | None = None,
) -> DestinationAssessment:
    target = parse_destination(kind, identifier)
    host_name = target.host.host if target.host else None
    matches = matching_rules(
        rules,
        scope="destination",
        identifiers=identifier_candidates(target.canonical) if target.canonical else [],
        domains=domain_candidates(host_name, registrable_domain(host_name)),
    )
    top = matches[0] if matches else None
    allow = next((r for r in matches if r.trust_level in ALLOW_LEVELS), None)
    block = next((r for r in matches if r.trust_level in BLOCK_LEVELS), None)

    checks: list[dict[str, str]] = []
    if allow is None:
        checks.append(_check("allowlist", "warn", "Not on the organisation's destination allowlist."))
    elif allow is top:
        checks.append(_check("allowlist", "pass", f"Matches allowlist rule '{allow.name}' ({allow.trust_level})."))
    else:
        checks.append(_check(
            "allowlist", "warn",
            f"Matches allowlist rule '{allow.name}', but the higher-priority rule '{top.name}' takes precedence.",
        ))
    if block is None:
        checks.append(_check("blocklist", "pass", "Does not match any blocking or suspicious-destination rule."))
    else:
        detail = f"Matches rule '{block.name}', which classifies it as {block.trust_level}."
        if block is not top:
            detail += f" The higher-priority rule '{top.name}' takes precedence."
        checks.append(_check("blocklist", "fail" if block is top else "warn", detail))

    signals: list[str] = []
    loopback = False
    if target.host is not None:
        loopback = _address_checks(target.host, checks, signals)
        _name_checks(target, allowlisted_domains(rules), checks, signals)
    checks.append(_history_check(history))

    reasons: list[str] = []
    if top is not None:
        classification = top.trust_level
        reasons.append(f"Matches {describe_rule(top)}, which classifies it as {classification}.")
        if signals and classification in (TrustLevel.EXTERNAL, TrustLevel.UNKNOWN):
            classification = TrustLevel.SUSPICIOUS.value
            reasons.append(
                "That rule does not explicitly trust this destination, and the checks below found warning signs, "
                "so it is treated as SUSPICIOUS."
            )
            reasons.extend(signals)
        elif signals and classification in ALLOW_LEVELS:
            reasons.extend(signals)
            reasons.append("The rule allows it anyway; review the rule if that was not intended.")
        else:
            reasons.extend(signals)
    elif signals:
        classification = TrustLevel.SUSPICIOUS.value
        reasons.extend(signals)
    elif loopback:
        classification = TrustLevel.APPROVED.value
        reasons.append("It is a loopback destination: the data stays on this machine, so it is approved by default.")
    else:
        classification = TrustLevel.UNKNOWN.value
        reasons.append("It is not on the organisation's destination allowlist, so it is classified as UNKNOWN.")
    reasons.append(_scope_reason(target))
    return DestinationAssessment(
        classification=str(classification),
        checks=checks,
        reasons=reasons,
        matched_rule_id=top.id if top else None,
        canonical_identifier=target.canonical,
        kind=target.kind,
    )
