"""Passive technology fingerprint signals from public response data."""

from webhacking_lab.http_client.models import NormalizedResponse
from webhacking_lab.scanner.models import TechnologyFingerprint


def fingerprint_response(response: NormalizedResponse) -> list[TechnologyFingerprint]:
    """Return explainable low/medium-confidence signals without claiming certainty."""

    headers = {item.name.lower(): item.value for item in response.headers}
    body_lower = response.body[:200_000].lower()
    signals: list[TechnologyFingerprint] = []
    server = headers.get("server")
    if server:
        signals.append(
            TechnologyFingerprint(
                name=server[:120], evidence="Server response header", confidence=0.65
            )
        )
    powered_by = headers.get("x-powered-by")
    if powered_by:
        signals.append(
            TechnologyFingerprint(
                name=powered_by[:120], evidence="X-Powered-By response header", confidence=0.75
            )
        )
    for name, marker, evidence in (
        ("Django", "csrfmiddlewaretoken", "Django CSRF field marker"),
        ("Flask", "werkzeug", "Werkzeug response marker"),
        ("FastAPI", '"openapi"', "OpenAPI response marker"),
        ("PHP", "phpsessid", "PHP session cookie marker"),
        ("Express", "connect.sid", "Express session cookie marker"),
        ("GraphQL", "__schema", "GraphQL schema marker"),
    ):
        cookie_text = " ".join(item.name.lower() for item in response.cookies)
        if marker in body_lower or marker in cookie_text:
            signals.append(TechnologyFingerprint(name=name, evidence=evidence, confidence=0.55))
    unique: dict[str, TechnologyFingerprint] = {}
    for signal in signals:
        unique.setdefault(signal.name.lower(), signal)
    return list(unique.values())
