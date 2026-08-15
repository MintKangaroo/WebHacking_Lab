"""Allowlist, SSRF, and DNS policy tests."""

from collections.abc import Sequence
from uuid import uuid4

import pytest

from webhacking_lab.http_client.models import ScopeRuleSpec
from webhacking_lab.http_client.scope_guard import ScopeGuard


class FakeResolver:
    def __init__(self, answers: Sequence[str]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, int]] = []

    async def resolve(self, hostname: str, port: int) -> Sequence[str]:
        self.calls.append((hostname, port))
        return self.answers


@pytest.mark.asyncio
async def test_scope_allows_exact_public_rule_and_returns_dns_pin_set() -> None:
    rule_id = uuid4()
    resolver = FakeResolver(["203.0.113.10", "203.0.113.11"])
    guard = ScopeGuard(resolver)
    rule = ScopeRuleSpec(
        id=rule_id,
        scheme="https",
        hostname="ctf.example",
        path_prefix="/challenge",
    )

    decision = await guard.check("https://ctf.example/challenge/one?token=secret", [rule])

    assert decision.allowed is True
    assert decision.matched_rule_id == rule_id
    assert decision.resolved_ips == ["203.0.113.10", "203.0.113.11"]
    assert decision.normalized_url == "https://ctf.example:443/challenge/one"
    assert resolver.calls == [("ctf.example", 443)]


@pytest.mark.asyncio
async def test_scope_requires_matching_scheme_port_host_and_path() -> None:
    resolver = FakeResolver(["198.51.100.8"])
    guard = ScopeGuard(resolver)
    rule = ScopeRuleSpec(
        scheme="https",
        hostname="ctf.example",
        port=8443,
        path_prefix="/allowed",
    )

    assert not (await guard.check("https://ctf.example/allowed", [rule])).allowed
    assert not (await guard.check("https://ctf.example:8443/not-allowed", [rule])).allowed
    assert not (await guard.check("http://ctf.example:8443/allowed", [rule])).allowed


@pytest.mark.asyncio
async def test_scope_subdomain_rule_does_not_match_suffix_confusion() -> None:
    guard = ScopeGuard(FakeResolver(["198.51.100.9"]))
    rule = ScopeRuleSpec(
        scheme="https",
        hostname="example.test",
        allow_subdomains=True,
    )

    assert (await guard.check("https://api.example.test/", [rule])).allowed
    assert not (await guard.check("https://example.test.attacker.invalid/", [rule])).allowed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("file:///etc/passwd", "scheme_blocked"),
        ("http://user:pass@localhost/", "userinfo_blocked"),
        ("http:///missing", "missing_hostname"),
        ("http://localhost:99999/", "malformed_url"),
        ("http://169.254.169.254/latest/meta-data", "metadata_blocked"),
        ("http://metadata.google.internal/", "metadata_blocked"),
    ],
)
async def test_scope_rejects_unsafe_authorities_before_dns(url: str, code: str) -> None:
    decision = await ScopeGuard(FakeResolver(["127.0.0.1"])).check(url, [])
    assert decision.allowed is False
    assert decision.code == code


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer",
    ["0.0.0.0", "224.0.0.1", "169.254.1.2", "240.0.0.1"],  # noqa: S104
)
async def test_scope_blocks_special_dns_answers_even_when_host_is_registered(answer: str) -> None:
    rule = ScopeRuleSpec(scheme="http", hostname="lab.example")
    decision = await ScopeGuard(FakeResolver([answer])).check("http://lab.example/", [rule])
    assert decision.allowed is False
    assert decision.code == "ip_policy_blocked"


@pytest.mark.asyncio
async def test_scope_fails_closed_on_empty_or_invalid_dns() -> None:
    rule = ScopeRuleSpec(scheme="http", hostname="lab.example")
    empty = await ScopeGuard(FakeResolver([])).check("http://lab.example/", [rule])
    invalid = await ScopeGuard(FakeResolver(["not-an-ip"])).check("http://lab.example/", [rule])
    assert empty.code == "dns_failed"
    assert invalid.code == "dns_invalid_answer"


@pytest.mark.asyncio
async def test_loopback_literal_requires_explicit_rule() -> None:
    guard = ScopeGuard()
    denied = await guard.check("http://127.0.0.1:5000/", [])
    allowed = await guard.check(
        "http://127.0.0.1:5000/",
        [ScopeRuleSpec(scheme="http", hostname="127.0.0.1", port=5000)],
    )
    assert denied.code == "not_in_scope"
    assert allowed.allowed is True


@pytest.mark.asyncio
async def test_ipv6_loopback_is_treated_like_ipv4_loopback() -> None:
    # ``::1`` is flagged is_reserved while 127.0.0.1 is not; both are loopback
    # and must reach the same allowlist decision (registered rule -> allowed).
    guard = ScopeGuard()
    denied = await guard.check("http://[::1]:5000/", [])
    allowed = await guard.check(
        "http://[::1]:5000/",
        [ScopeRuleSpec(scheme="http", hostname="::1", port=5000)],
    )
    assert denied.code == "not_in_scope"
    assert allowed.allowed is True


@pytest.mark.asyncio
async def test_reserved_non_loopback_ipv6_answer_is_still_blocked() -> None:
    # The loopback exemption must not reopen the rest of the reserved space.
    rule = ScopeRuleSpec(scheme="http", hostname="lab.example")
    decision = await ScopeGuard(FakeResolver(["100::1"])).check(
        "http://lab.example/", [rule]
    )
    assert decision.allowed is False
    assert decision.code == "ip_policy_blocked"


@pytest.mark.asyncio
async def test_scope_rule_without_port_allows_registered_host_on_any_port() -> None:
    decision = await ScopeGuard().check(
        "http://127.0.0.1:5000/",
        [ScopeRuleSpec(scheme="http", hostname="127.0.0.1")],
    )
    assert decision.allowed is True
