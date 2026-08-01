"""SSRF-resistant scope validation shared by all future execution paths."""

import asyncio
import ipaddress
import socket
from collections.abc import Sequence
from typing import Protocol
from urllib.parse import urlsplit

from webhacking_lab.domain.exceptions import ImportFormatError
from webhacking_lab.http_client.models import ScopeDecision, ScopeRuleSpec
from webhacking_lab.http_client.request_normalizer import normalize_hostname

METADATA_HOSTNAMES = frozenset(
    {
        "metadata.google.internal",
        "metadata.google.internal.",
        "instance-data",
        "169.254.169.254",
        "100.100.100.200",
    }
)
METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("100.100.100.200"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)


class DnsResolver(Protocol):
    """Injectable resolver boundary used by rebinding regression tests."""

    async def resolve(self, hostname: str, port: int) -> Sequence[str]:
        """Resolve all current addresses for a hostname."""


class SystemDnsResolver:
    """Resolve DNS without connecting to the target service."""

    async def resolve(self, hostname: str, port: int) -> Sequence[str]:
        loop = asyncio.get_running_loop()
        try:
            records = await loop.getaddrinfo(
                hostname,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror:
            return []
        return sorted({str(record[4][0]) for record in records})


def _hostname_matches(hostname: str, rule: ScopeRuleSpec) -> bool:
    if hostname == rule.hostname:
        return True
    return rule.allow_subdomains and hostname.endswith(f".{rule.hostname}")


def _path_matches(path: str, prefix: str) -> bool:
    normalized_prefix = prefix if prefix.startswith("/") else f"/{prefix}"
    if normalized_prefix == "/":
        return True
    normalized_prefix = normalized_prefix.rstrip("/")
    return path == normalized_prefix or path.startswith(f"{normalized_prefix}/")


def _matching_rule(
    *,
    scheme: str,
    hostname: str,
    port: int,
    path: str,
    rules: Sequence[ScopeRuleSpec],
) -> ScopeRuleSpec | None:
    for rule in rules:
        if (
            rule.scheme == scheme
            and (rule.port is None or rule.port == port)
            and _hostname_matches(hostname, rule)
            and _path_matches(path, rule.path_prefix)
        ):
            return rule
    return None


def _blocked_ip_reason(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    comparable = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    effective = comparable or address
    if effective in METADATA_ADDRESSES:
        return "Cloud metadata addresses are always blocked"
    if effective.is_unspecified:
        return "Unspecified addresses are blocked"
    if effective.is_multicast:
        return "Multicast addresses are blocked"
    if effective.is_link_local:
        return "Link-local addresses are blocked"
    if effective.is_reserved:
        return "Reserved addresses are blocked"
    return None


class ScopeGuard:
    """Validate a URL and return the approved DNS answers for future pinning."""

    def __init__(self, resolver: DnsResolver | None = None) -> None:
        self._resolver = resolver or SystemDnsResolver()

    async def check(self, url: str, rules: Sequence[ScopeRuleSpec]) -> ScopeDecision:
        """Apply scheme, authority, DNS/IP, allowlist, and path checks in order."""

        try:
            parsed = urlsplit(url)
            parsed_port = parsed.port
        except ValueError:
            return ScopeDecision(
                allowed=False,
                code="malformed_url",
                reason="URL authority or port is malformed",
            )
        scheme = parsed.scheme.lower()
        if parsed.username is not None or parsed.password is not None:
            return ScopeDecision(
                allowed=False,
                code="userinfo_blocked",
                reason="URLs containing user information are blocked",
            )
        if scheme not in {"http", "https"}:
            return ScopeDecision(
                allowed=False,
                code="scheme_blocked",
                reason="Only http and https schemes are allowed",
            )
        if parsed.hostname is None:
            return ScopeDecision(
                allowed=False,
                code="missing_hostname",
                reason="URL hostname is required",
            )
        try:
            hostname = normalize_hostname(parsed.hostname)
        except ImportFormatError:
            return ScopeDecision(
                allowed=False,
                code="invalid_hostname",
                reason="URL hostname is invalid",
            )
        port = parsed_port or (80 if scheme == "http" else 443)
        path = parsed.path or "/"
        display_host = f"[{hostname}]" if ":" in hostname else hostname
        normalized_url = f"{scheme}://{display_host}:{port}{path}"
        if hostname in METADATA_HOSTNAMES or hostname.endswith(".internal.metadata"):
            return ScopeDecision(
                allowed=False,
                code="metadata_blocked",
                reason="Cloud metadata hostnames are always blocked",
                hostname=hostname,
                normalized_url=normalized_url,
            )

        try:
            literal_ip = ipaddress.ip_address(hostname)
            answers = [str(literal_ip)]
        except ValueError:
            answers = list(await self._resolver.resolve(hostname, port))
        if not answers:
            return ScopeDecision(
                allowed=False,
                code="dns_failed",
                reason="Hostname did not resolve to an address",
                hostname=hostname,
                normalized_url=normalized_url,
            )

        parsed_answers: list[str] = []
        for answer in answers:
            try:
                address = ipaddress.ip_address(answer)
            except ValueError:
                return ScopeDecision(
                    allowed=False,
                    code="dns_invalid_answer",
                    reason="DNS returned a non-IP answer",
                    hostname=hostname,
                    normalized_url=normalized_url,
                )
            reason = _blocked_ip_reason(address)
            if reason:
                return ScopeDecision(
                    allowed=False,
                    code="ip_policy_blocked",
                    reason=reason,
                    hostname=hostname,
                    normalized_url=normalized_url,
                    resolved_ips=[str(address)],
                )
            parsed_answers.append(str(address))

        rule = _matching_rule(
            scheme=scheme,
            hostname=hostname,
            port=port,
            path=path,
            rules=rules,
        )
        if rule is None:
            return ScopeDecision(
                allowed=False,
                code="not_in_scope",
                reason="URL does not match a registered scope rule",
                hostname=hostname,
                normalized_url=normalized_url,
                resolved_ips=parsed_answers,
            )
        return ScopeDecision(
            allowed=True,
            code="allowed",
            reason="URL and all resolved addresses passed scope policy",
            hostname=hostname,
            normalized_url=normalized_url,
            resolved_ips=parsed_answers,
            matched_rule_id=rule.id,
        )
