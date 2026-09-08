"""Consolidate static and scanner findings for a project into one report."""

from collections import Counter
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.api.schemas.reports import (
    HybridCorrelation,
    HybridReport,
    HybridRuntimeSignal,
    ProjectReport,
    ReportFinding,
    ReportFindingDetail,
    ReportFlowStep,
    ReportSummary,
)
from webhacking_lab.database.models import (
    CodeFile,
    CodeProject,
    ScanFinding,
    ScanJob,
    ScanTestCase,
    StaticFindingRecord,
    StaticRouteRecord,
)
from webhacking_lab.database.repositories.projects import ProjectRepository
from webhacking_lab.domain.enums import (
    ActiveTestStatus,
    Severity,
    VerificationStatus,
)
from webhacking_lab.domain.exceptions import EntityNotFoundError
from webhacking_lab.services.hybrid import (
    CorrelationResult,
    RuntimeSignal,
    StaticCandidate,
    correlate,
)

# Highest impact first; unknown severities sort last but stay grouped.
_SEVERITY_RANK = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFO.value: 4,
}


def _finding_rank(finding: ReportFinding) -> tuple[int, str, str, str]:
    return (
        _SEVERITY_RANK.get(finding.severity, len(_SEVERITY_RANK)),
        finding.source,
        finding.category,
        finding.title,
    )


class ReportService:
    """Bundle every persisted finding under a project into a single report."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._projects = ProjectRepository(session)

    async def build(self, project_id: UUID) -> ProjectReport:
        project = await self._projects.get(project_id)
        if project is None:
            raise EntityNotFoundError("Project was not found")
        correlation = await self._correlate(project_id)
        findings = [
            *await self._static_findings(project_id, correlation),
            *await self._scanner_findings(project_id, correlation),
        ]
        findings.sort(key=_finding_rank)
        return ProjectReport(
            project_id=project_id,
            project_name=project.name,
            generated_at=datetime.now(UTC),
            summary=_summarize(findings),
            findings=findings,
        )

    async def hybrid(self, project_id: UUID) -> HybridReport:
        project = await self._projects.get(project_id)
        if project is None:
            raise EntityNotFoundError("Project was not found")
        candidates = await self._static_candidates(project_id)
        signals = await self._runtime_signals(project_id)
        result = correlate(candidates, signals)
        correlations = [
            HybridCorrelation(
                category=item.static.category,
                severity=item.static.severity,
                verification=item.verification,
                note=item.note,
                static_origin_id=item.static.origin_id,
                static_title=item.static.title,
                static_location=item.static.location,
                parameter=item.static.parameter,
                runtime=[
                    HybridRuntimeSignal(
                        origin_id=signal.origin_id,
                        kind=signal.kind,
                        endpoint_url=signal.endpoint_url,
                        parameter=signal.parameter,
                        verification=signal.verification,
                        confidence=signal.confidence,
                        title=signal.title,
                        evidence=signal.evidence,
                    )
                    for signal in item.runtime
                ],
            )
            for item in result.correlations
        ]
        correlations.sort(key=lambda item: _SEVERITY_RANK.get(item.severity, len(_SEVERITY_RANK)))
        by_verification = Counter(item.verification for item in correlations)
        return HybridReport(
            project_id=project_id,
            project_name=project.name,
            generated_at=datetime.now(UTC),
            total_static=len(candidates),
            correlated=len(correlations),
            by_verification=dict(by_verification),
            correlations=correlations,
        )

    async def _correlate(self, project_id: UUID) -> CorrelationResult:
        candidates = await self._static_candidates(project_id)
        signals = await self._runtime_signals(project_id)
        return correlate(candidates, signals)

    async def _static_candidates(self, project_id: UUID) -> list[StaticCandidate]:
        rows = await self._session.execute(
            select(StaticFindingRecord, CodeFile.relative_path, StaticRouteRecord.path)
            .join(CodeProject, StaticFindingRecord.code_project_id == CodeProject.id)
            .join(CodeFile, StaticFindingRecord.code_file_id == CodeFile.id)
            .outerjoin(
                StaticRouteRecord,
                StaticFindingRecord.static_route_id == StaticRouteRecord.id,
            )
            .where(CodeProject.project_id == project_id)
        )
        return [
            StaticCandidate(
                origin_id=record.id,
                category=record.category,
                parameter=record.parameter,
                path=route_path,
                title=record.title,
                severity=record.severity,
                location=f"{path}:{record.sink_line}",
            )
            for record, path, route_path in rows.all()
        ]

    async def _runtime_signals(self, project_id: UUID) -> list[RuntimeSignal]:
        # Active SAFE tests that actually ran carry the richest evidence (parameter and
        # an explicit attempted state), so they are the primary runtime source.
        test_rows = (
            await self._session.scalars(
                select(ScanTestCase)
                .join(ScanJob, ScanTestCase.scan_id == ScanJob.id)
                .where(
                    ScanJob.project_id == project_id,
                    ScanTestCase.status.in_(
                        [ActiveTestStatus.COMPLETED, ActiveTestStatus.INCONCLUSIVE]
                    ),
                )
            )
        ).all()
        signals: list[RuntimeSignal] = [
            RuntimeSignal(
                origin_id=test.id,
                kind="active_test",
                category=test.category,
                endpoint_url=test.endpoint_url,
                parameter=test.parameter,
                verification=test.result_status or VerificationStatus.NOT_TESTED.value,
                confidence=test.confidence,
                title=test.title,
                evidence=[_flatten_evidence(item) for item in test.evidence_json],
                attempted=True,
            )
            for test in test_rows
        ]
        # Passive findings supplement the active tests. A finding produced by an active
        # test is already represented above, so skip any whose (endpoint, category) an
        # active test already covers to avoid double-counting the same observation.
        covered = {(test.endpoint_url, test.category) for test in test_rows}
        finding_rows = (
            await self._session.scalars(
                select(ScanFinding)
                .join(ScanJob, ScanFinding.scan_id == ScanJob.id)
                .where(
                    ScanJob.project_id == project_id,
                    ScanFinding.status != VerificationStatus.NOT_TESTED.value,
                )
            )
        ).all()
        signals.extend(
            RuntimeSignal(
                origin_id=finding.id,
                kind="passive_finding",
                category=finding.category,
                endpoint_url=finding.endpoint_url,
                parameter=None,
                verification=finding.status,
                confidence=finding.confidence,
                title=finding.title,
                evidence=[_flatten_evidence(item) for item in finding.evidence_json],
            )
            for finding in finding_rows
            if (finding.endpoint_url, finding.category) not in covered
        )
        return signals

    async def finding_detail(
        self, project_id: UUID, source: str, origin_id: UUID
    ) -> ReportFindingDetail:
        if source == "static":
            detail = await self._static_detail(project_id, origin_id)
        elif source == "scanner":
            detail = await self._scanner_detail(project_id, origin_id)
        else:
            raise EntityNotFoundError("Unknown finding source")
        if detail is None:
            raise EntityNotFoundError("Finding was not found for this project")
        return detail

    async def _static_detail(
        self, project_id: UUID, origin_id: UUID
    ) -> ReportFindingDetail | None:
        row = (
            await self._session.execute(
                select(StaticFindingRecord, CodeFile.relative_path)
                .join(CodeProject, StaticFindingRecord.code_project_id == CodeProject.id)
                .join(CodeFile, StaticFindingRecord.code_file_id == CodeFile.id)
                .where(
                    CodeProject.project_id == project_id,
                    StaticFindingRecord.id == origin_id,
                )
            )
        ).first()
        if row is None:
            return None
        record, path = row
        remediation = record.remediation_json or {}
        guidance = [
            line
            for line in (remediation.get("summary"), *remediation.get("guidance", []))
            if line
        ]
        if remediation.get("verification"):
            guidance.append(f"Verify: {remediation['verification']}")
        return ReportFindingDetail(
            source="static",
            origin_id=record.id,
            category=record.category,
            title=record.title,
            severity=record.severity,
            status=record.status,
            confidence=record.confidence,
            location=f"{path}:{record.sink_line}",
            summary=f"{record.source_label} → {record.sink_label}",
            flow_steps=[
                ReportFlowStep(
                    kind=step.get("kind", ""),
                    label=step.get("label", ""),
                    line=step.get("line", 0),
                    detail=step.get("detail", ""),
                )
                for step in record.flow_steps_json
            ],
            evidence=list(record.evidence_json),
            remediation=guidance,
            safe_example=remediation.get("safe_example"),
            limitations=list(record.limitations_json),
        )

    async def _scanner_detail(
        self, project_id: UUID, origin_id: UUID
    ) -> ReportFindingDetail | None:
        record = (
            await self._session.scalars(
                select(ScanFinding)
                .join(ScanJob, ScanFinding.scan_id == ScanJob.id)
                .where(ScanJob.project_id == project_id, ScanFinding.id == origin_id)
            )
        ).first()
        if record is None:
            return None
        return ReportFindingDetail(
            source="scanner",
            origin_id=record.id,
            category=record.category,
            title=record.title,
            severity=record.severity,
            status=record.status,
            confidence=record.confidence,
            location=record.endpoint_url,
            summary=record.summary,
            flow_steps=[],
            evidence=[_flatten_evidence(item) for item in record.evidence_json],
            remediation=list(record.remediation_json),
            safe_example=None,
            limitations=list(record.limitations_json),
        )

    async def _static_findings(
        self, project_id: UUID, correlation: CorrelationResult
    ) -> list[ReportFinding]:
        rows = await self._session.execute(
            select(StaticFindingRecord, CodeFile.relative_path)
            .join(CodeProject, StaticFindingRecord.code_project_id == CodeProject.id)
            .join(CodeFile, StaticFindingRecord.code_file_id == CodeFile.id)
            .where(CodeProject.project_id == project_id)
        )
        findings = []
        for record, path in rows.all():
            verification, count = correlation.static_verification.get(
                record.id, (VerificationStatus.NOT_TESTED.value, 0)
            )
            findings.append(
                ReportFinding(
                    source="static",
                    origin_id=record.id,
                    category=record.category,
                    title=record.title,
                    severity=record.severity,
                    status=record.status,
                    confidence=record.confidence,
                    location=f"{path}:{record.sink_line}",
                    detail=f"{record.source_label} \u2192 {record.sink_label}",
                    verification=verification,
                    correlation_count=count,
                )
            )
        return findings

    async def _scanner_findings(
        self, project_id: UUID, correlation: CorrelationResult
    ) -> list[ReportFinding]:
        records = await self._session.scalars(
            select(ScanFinding)
            .join(ScanJob, ScanFinding.scan_id == ScanJob.id)
            .where(
                ScanJob.project_id == project_id,
                ScanFinding.status != VerificationStatus.NOT_TESTED.value,
            )
        )
        return [
            ReportFinding(
                source="scanner",
                origin_id=record.id,
                category=record.category,
                title=record.title,
                severity=record.severity,
                status=record.status,
                confidence=record.confidence,
                location=record.endpoint_url,
                detail=record.summary,
                verification=record.status,
                correlation_count=len(correlation.scanner_root_cause.get(record.id, [])),
            )
            for record in records
        ]


def _summarize(findings: list[ReportFinding]) -> ReportSummary:
    return ReportSummary(
        total=len(findings),
        by_severity=dict(Counter(finding.severity for finding in findings)),
        by_category=dict(Counter(finding.category for finding in findings)),
        by_source=dict(Counter(finding.source for finding in findings)),
        by_status=dict(Counter(finding.status for finding in findings)),
    )


def render_report_markdown(report: ProjectReport) -> str:
    """Render a deterministic Markdown export of a consolidated report."""

    lines = [
        f"# Security Findings Report: {report.project_name}",
        "",
        f"- Generated: {report.generated_at.isoformat()}",
        f"- Total findings: {report.summary.total}",
        "",
        "## Summary by severity",
        "",
    ]
    if report.summary.by_severity:
        ordered = sorted(
            report.summary.by_severity.items(),
            key=lambda item: _SEVERITY_RANK.get(item[0], len(_SEVERITY_RANK)),
        )
        lines.extend(f"- {severity}: {count}" for severity, count in ordered)
    else:
        lines.append("- No findings recorded.")
    lines.extend(["", "## Findings", ""])
    if not report.findings:
        lines.append("No static or scanner findings were recorded for this project.")
        return "\n".join(lines) + "\n"
    lines.extend(
        [
            "| Severity | Source | Category | Title | Location | Status | Verification |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    lines.extend(_finding_row(finding) for finding in report.findings)
    return "\n".join(lines) + "\n"


def _finding_row(finding: ReportFinding) -> str:
    verification = finding.verification
    if finding.correlation_count:
        verification = f"{verification} (x{finding.correlation_count})"
    return (
        f"| {finding.severity} | {finding.source} | {finding.category} "
        f"| {_escape_cell(finding.title)} | {_escape_cell(finding.location)} "
        f"| {finding.status} | {verification} |"
    )


def _escape_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _flatten_evidence(item: dict[str, object]) -> str:
    return ", ".join(f"{key}: {value}" for key, value in item.items())
