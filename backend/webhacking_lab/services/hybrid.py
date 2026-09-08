"""Correlate inert static source-to-sink candidates with runtime scanner evidence.

This module performs no network execution and touches no execution boundary. It is a
pure, database-independent derivation over findings that are already persisted: static
candidates from the source analyzer and runtime signals from the SAFE scanner (approved
active tests and passive findings). Correlating the two lets a static candidate's
evidence maturity be promoted by real runtime observation, and lets a scanner finding
point back to the source location that explains it.

Promotion is deliberately conservative: a runtime test that ran without reproducing the
issue never downgrades a candidate to a false positive on its own; it only annotates
that the runtime attempt did not reproduce it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from webhacking_lab.domain.enums import VerificationStatus

# Segment markers used by the frameworks we extract routes from: Flask ``<id>``,
# Express/FastAPI ``:id``/``{id}``, Django converters ``<int:id>``.
_PLACEHOLDER_PREFIXES = ("{", ":", "<")

# Evidence maturity ranking; a higher rank is stronger runtime confirmation.
_VERIFICATION_RANK = {
    VerificationStatus.CONFIRMED.value: 4,
    VerificationStatus.LIKELY.value: 3,
    VerificationStatus.SUSPICIOUS.value: 2,
    VerificationStatus.OBSERVATION.value: 1,
}

RuntimeKind = Literal["active_test", "passive_finding"]


@dataclass(frozen=True)
class StaticCandidate:
    """A source-only finding reduced to what correlation needs."""

    origin_id: UUID
    category: str
    parameter: str | None
    path: str | None
    title: str
    severity: str
    location: str


@dataclass(frozen=True)
class RuntimeSignal:
    """A runtime scanner observation reduced to what correlation needs."""

    origin_id: UUID
    kind: RuntimeKind
    category: str
    endpoint_url: str
    parameter: str | None
    verification: str
    confidence: float | None
    title: str
    evidence: list[str] = field(default_factory=list)
    # For active tests: the request was actually issued (approved and run), even if it
    # produced no positive signal. Passive findings are never "attempted" in this sense.
    attempted: bool = False


@dataclass(frozen=True)
class Correlation:
    """One static candidate joined to every runtime signal that matches it."""

    static: StaticCandidate
    runtime: list[RuntimeSignal]
    verification: str
    note: str | None


@dataclass(frozen=True)
class CorrelationResult:
    """Everything a report needs after correlating static and runtime findings."""

    correlations: list[Correlation]
    # Every static candidate id -> (derived verification, matched runtime count).
    static_verification: dict[UUID, tuple[str, int]]
    # Runtime signal id -> static candidate ids that share a root cause with it.
    scanner_root_cause: dict[UUID, list[UUID]]


def normalize_path(value: str | None) -> tuple[str, ...]:
    """Reduce a URL or route template to its lowercased path segments.

    Scheme, host, query and fragment are dropped so an absolute runtime URL and a
    relative route template compare on the same axis.
    """

    if not value:
        return ()
    raw = value.strip()
    path = urlsplit(raw).path if "://" in raw else raw.split("?", 1)[0].split("#", 1)[0]
    return tuple(segment.lower() for segment in path.split("/") if segment)


def _is_placeholder(segment: str) -> bool:
    return segment.startswith(_PLACEHOLDER_PREFIXES)


def path_matches(template: str | None, url: str | None) -> bool:
    """Whether a runtime URL path satisfies a route template.

    Placeholder segments (``{id}``, ``:id``, ``<int:id>``) match any single segment;
    every other segment must be equal. An empty template (no route linked) matches
    nothing here — callers fall back to category/parameter matching in that case.
    """

    template_segments = normalize_path(template)
    url_segments = normalize_path(url)
    if not template_segments or len(template_segments) != len(url_segments):
        return False
    return all(
        _is_placeholder(expected) or expected == actual
        for expected, actual in zip(template_segments, url_segments, strict=True)
    )


def _signals_match(static: StaticCandidate, runtime: RuntimeSignal) -> bool:
    if static.category != runtime.category:
        return False
    # When both name a parameter, they must agree; a missing side stays permissive.
    if static.parameter and runtime.parameter and static.parameter != runtime.parameter:
        return False
    if static.path:
        return path_matches(static.path, runtime.endpoint_url)
    # No route was linked to the static finding: fall back to a parameter match so we
    # do not correlate unrelated endpoints purely on a shared category.
    return bool(static.parameter and runtime.parameter)


def derive_verification(matches: list[RuntimeSignal]) -> tuple[str, str | None]:
    """Promote a static candidate from the strongest runtime signal that matches it.

    Returns the derived :class:`VerificationStatus` value and an optional human note.
    Runtime tests that ran without reproducing the issue never yield a false positive;
    they only annotate the attempt.
    """

    if not matches:
        return VerificationStatus.NOT_TESTED.value, None
    best_rank = 0
    best_status = VerificationStatus.NOT_TESTED.value
    attempted = False
    for signal in matches:
        attempted = attempted or signal.attempted
        rank = _VERIFICATION_RANK.get(signal.verification, 0)
        if rank > best_rank:
            best_rank = rank
            best_status = signal.verification
    if best_rank > 0:
        return best_status, None
    if attempted:
        return (
            VerificationStatus.NOT_TESTED.value,
            "Runtime SAFE test was executed but did not reproduce this candidate.",
        )
    return VerificationStatus.NOT_TESTED.value, None


def correlate(
    static_findings: list[StaticCandidate],
    runtime_signals: list[RuntimeSignal],
) -> CorrelationResult:
    """Join static candidates to runtime signals and derive verification for each."""

    correlations: list[Correlation] = []
    static_verification: dict[UUID, tuple[str, int]] = {}
    scanner_root_cause: dict[UUID, list[UUID]] = {}
    for static in static_findings:
        matches = [signal for signal in runtime_signals if _signals_match(static, signal)]
        verification, note = derive_verification(matches)
        static_verification[static.origin_id] = (verification, len(matches))
        if matches:
            correlations.append(
                Correlation(
                    static=static,
                    runtime=matches,
                    verification=verification,
                    note=note,
                )
            )
            for signal in matches:
                scanner_root_cause.setdefault(signal.origin_id, []).append(static.origin_id)
    return CorrelationResult(
        correlations=correlations,
        static_verification=static_verification,
        scanner_root_cause=scanner_root_cause,
    )
