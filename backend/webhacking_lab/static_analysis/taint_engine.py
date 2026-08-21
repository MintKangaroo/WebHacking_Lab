"""Language-routed, bounded source-to-sink analysis coordinator."""

from pathlib import Path

from webhacking_lab.static_analysis.languages.javascript.parser import (
    analyze_javascript_taint,
)
from webhacking_lab.static_analysis.languages.php.parser import analyze_php_taint
from webhacking_lab.static_analysis.languages.python.taint_rules import analyze_python_taint
from webhacking_lab.static_analysis.models import (
    ExtractedRoute,
    IndexedFile,
    StaticAnalysisExtraction,
)

MAX_TAINT_FILE_BYTES = 1_000_000


def analyze_static_data_flows(
    root: Path,
    files: list[IndexedFile],
    routes: list[ExtractedRoute],
) -> StaticAnalysisExtraction:
    """Run inert language parsers within fixed per-file and finding budgets."""

    findings = []
    warnings: list[str] = []
    safe_decisions: list[str] = []
    for entry in files:
        if entry.language not in {"python", "php", "javascript"}:
            continue
        if entry.size_bytes > MAX_TAINT_FILE_BYTES:
            warnings.append(f"Skipped oversized taint input: {entry.relative_path}")
            continue
        content = (root / entry.relative_path).read_text(encoding="utf-8", errors="replace")
        try:
            if entry.language == "python":
                detected, safe = analyze_python_taint(content, entry.relative_path, routes)
            elif entry.language == "javascript":
                detected, safe = analyze_javascript_taint(content, entry.relative_path, routes)
            else:
                detected, safe = analyze_php_taint(content, entry.relative_path, routes)
        except (SyntaxError, ValueError, TypeError) as error:
            warnings.append(
                f"Skipped malformed {entry.language} taint input: "
                f"{entry.relative_path} ({type(error).__name__})"
            )
            continue
        findings.extend(detected)
        safe_decisions.extend(safe)
        if len(findings) >= 500:
            warnings.append("Static finding budget reached; remaining files were not analyzed")
            break
    return StaticAnalysisExtraction(
        findings=findings[:500],
        warnings=sorted(set(warnings))[:100],
        safe_decisions=sorted(set(safe_decisions))[:100],
    )
