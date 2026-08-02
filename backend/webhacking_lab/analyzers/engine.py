"""Deterministic passive analyzer orchestration."""

import asyncio
from collections.abc import Sequence

from webhacking_lab.analyzers import (
    AuthenticationAnalyzer,
    CorsAnalyzer,
    InjectionIndicatorAnalyzer,
    JwtStructureAnalyzer,
    SecurityHeaderAnalyzer,
    XssReflectionAnalyzer,
)
from webhacking_lab.analyzers.models import (
    AnalysisContext,
    AnalysisFlow,
    AnalysisResult,
    Analyzer,
    FlowEdge,
    FlowNode,
)
from webhacking_lab.http_client.models import NormalizedRequest, NormalizedResponse


def default_analyzers() -> tuple[Analyzer, ...]:
    """Return the initial six passive analyzers in stable display order."""

    return (
        SecurityHeaderAnalyzer(),
        CorsAnalyzer(),
        JwtStructureAnalyzer(),
        XssReflectionAnalyzer(),
        InjectionIndicatorAnalyzer(),
        AuthenticationAnalyzer(),
    )


class AnalysisEngine:
    """Run pure passive plugins concurrently over already-redacted evidence."""

    def __init__(self, analyzers: Sequence[Analyzer] | None = None) -> None:
        self._analyzers = tuple(analyzers or default_analyzers())

    async def analyze(
        self,
        request: NormalizedRequest,
        response: NormalizedResponse | None,
        context: AnalysisContext,
    ) -> list[AnalysisResult]:
        """Run plugins without network access or automatic test execution."""

        return list(
            await asyncio.gather(
                *(analyzer.analyze(request, response, context) for analyzer in self._analyzers)
            )
        )

    @staticmethod
    def flow(results: Sequence[AnalysisResult]) -> AnalysisFlow:
        """Build an explainable analysis workflow for React Flow."""

        nodes = [
            FlowNode(
                id="normalize",
                label="Normalize & Redact",
                status="confirmed",
                detail="Sensitive values were masked before analysis.",
                confidence=1,
            ),
            FlowNode(
                id="passive",
                label="Passive Analysis",
                status="confirmed",
                detail=f"{len(results)} transport-independent analyzers completed.",
                confidence=1,
            ),
        ]
        edges = [FlowEdge(id="normalize-passive", source="normalize", target="passive")]
        for index, result in enumerate(results):
            node_id = f"result-{index}"
            nodes.append(
                FlowNode(
                    id=node_id,
                    label=result.title,
                    status=result.status.value,
                    detail=result.summary,
                    confidence=result.confidence,
                )
            )
            edges.append(FlowEdge(id=f"passive-{node_id}", source="passive", target=node_id))
        return AnalysisFlow(nodes=nodes, edges=edges)
