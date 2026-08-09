"""Central mutation builder and destructive-value deny policy for SAFE tests."""

import re

from webhacking_lab.analyzers.models import TestCase
from webhacking_lab.domain.exceptions import ExecutionPolicyError
from webhacking_lab.http_client.models import NameValue, NormalizedRequest

FORBIDDEN_VALUE = re.compile(
    r"(?i)(?:;|--|/\*|\b(?:drop|delete|update|insert|alter|truncate|exec|execute|sleep|benchmark)\b)"
)


def build_safe_test_request(
    baseline: NormalizedRequest,
    test_case: TestCase,
) -> NormalizedRequest:
    """Apply only an allowlisted query replacement or one OPTIONS Origin header."""

    if test_case.destructive or test_case.max_requests != 1:
        raise ExecutionPolicyError("SAFE tests must be non-destructive single requests")
    if FORBIDDEN_VALUE.search(test_case.preview_value):
        raise ExecutionPolicyError("The proposed value was blocked by the destructive-value policy")
    user_agent = NameValue(
        name="User-Agent",
        value="WebHacking-Lab/0.1 controlled-request",
    )
    if test_case.mutation_type == "cors_reserved_origin":
        return baseline.model_copy(
            update={
                "method": "OPTIONS",
                "headers": [
                    NameValue(name="Origin", value=test_case.preview_value),
                    NameValue(name="Access-Control-Request-Method", value="GET"),
                    user_agent,
                ],
                "body": "",
            }
        )
    allowed = {
        "sql_quote_append",
        "sql_boolean_true",
        "sql_boolean_false",
        "xss_inert_marker",
        "open_redirect_reserved_domain",
    }
    if test_case.mutation_type not in allowed or test_case.parameter is None:
        raise ExecutionPolicyError("The proposed mutation type is not allowed in SAFE mode")
    replaced = False
    query: list[NameValue] = []
    for item in baseline.query:
        if not replaced and item.name == test_case.parameter and not item.redacted:
            query.append(NameValue(name=item.name, value=test_case.preview_value))
            replaced = True
        else:
            query.append(item)
    if not replaced:
        raise ExecutionPolicyError("The selected unredacted query parameter no longer exists")
    return baseline.model_copy(
        update={"method": "GET", "query": query, "headers": [user_agent], "body": ""}
    )
