"""Consolidate static and scanner findings for a project into one report."""

from collections import Counter
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.api.schemas.reports import (
    ProjectReport,
    ReportFinding,
    ReportSummary,
)
from webhacking_lab.database.models import (
    CodeFile,
    CodeProject,
    ScanFinding,
    ScanJob,
    StaticFindingRecord,
)
from webhacking_lab.database.repositories.projects import ProjectRepository
from webhacking_lab.domain.enums import Severity, VerificationStatus
from webhacking_lab.domain.exceptions import EntityNotFoundError

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
        findings = [
            *await self._static_findings(project_id),
            *await self._scanner_findings(project_id),
        ]
        findings.sort(key=_finding_rank)
        return ProjectReport(
            project_id=project_id,
            project_name=project.name,
            generated_at=datetime.now(UTC),
            summary=_summarize(findings),
            findings=findings,
        )

    async def _static_findings(self, project_id: UUID) -> list[ReportFinding]:
        rows = await self._session.execute(
            select(StaticFindingRecord, CodeFile.relative_path)
            .join(CodeProject, StaticFindingRecord.code_project_id == CodeProject.id)
            .join(CodeFile, StaticFindingRecord.code_file_id == CodeFile.id)
            .where(CodeProject.project_id == project_id)
        )
        return [
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
            )
            for record, path in rows.all()
        ]

    async def _scanner_findings(self, project_id: UUID) -> list[ReportFinding]:
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
            "| Severity | Source | Category | Title | Location | Status |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    lines.extend(_finding_row(finding) for finding in report.findings)
    return "\n".join(lines) + "\n"


def _finding_row(finding: ReportFinding) -> str:
    return (
        f"| {finding.severity} | {finding.source} | {finding.category} "
        f"| {_escape_cell(finding.title)} | {_escape_cell(finding.location)} "
        f"| {finding.status} |"
    )


def _escape_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
