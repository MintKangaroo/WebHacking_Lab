"""Central mutation builder and destructive-value deny policy for scanner tests."""

import re

from webhacking_lab.analyzers.models import TestCase
from webhacking_lab.domain.enums import ScannerProfile
from webhacking_lab.domain.exceptions import ExecutionPolicyError
from webhacking_lab.http_client.models import NameValue, NormalizedRequest

FORBIDDEN_VALUE = re.compile(
    r"(?i)(?:;|--|/\*|\b(?:drop|delete|update|insert|alter|truncate|exec|execute|sleep|benchmark)\b)"
)

# CTF payloads are read-only single GET probes. Even in the relaxed CTF profile we
# never allow verbs or clauses that mutate, delete, or stall server-side state.
CTF_FORBIDDEN_VALUE = re.compile(
    r"(?i)\b(?:drop|delete|truncate|insert\s+into|update\s+\w+\s+set|"
    r"alter\s+table|sleep|benchmark|pg_sleep|waitfor\s+delay|shutdown|"
    r"load_file|into\s+outfile|into\s+dumpfile)\b"
)

CTF_MUTATION_TYPES = frozenset(
    {
        "ctf_sql_error",
        "ctf_sql_union",
        "ctf_sql_boolean_true",
        "ctf_sql_boolean_false",
        "ctf_xss_reflection",
        "ctf_path_traversal",
        "ctf_open_redirect",
    }
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


def build_ctf_test_request(
    baseline: NormalizedRequest,
    test_case: TestCase,
) -> NormalizedRequest:
    """Build one read-only CTF probe: a single GET with one query parameter replaced.

    CTF mode allows real detection payloads (a lone quote, a UNION marker, a
    traversal path, an inert script marker) but still refuses any value that would
    mutate, delete, or stall server-side state, and still sends exactly one request
    with no body or replayed credentials.
    """

    if test_case.max_requests != 1:
        raise ExecutionPolicyError("CTF tests must be non-stalling single requests")
    if test_case.mutation_type not in CTF_MUTATION_TYPES or test_case.parameter is None:
        raise ExecutionPolicyError("The proposed mutation type is not allowed in CTF mode")
    if CTF_FORBIDDEN_VALUE.search(test_case.preview_value):
        raise ExecutionPolicyError(
            "The proposed value was blocked by the CTF non-destructive-value policy"
        )
    user_agent = NameValue(name="User-Agent", value="WebHacking-Lab/0.1 ctf-request")
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


def build_test_request(
    baseline: NormalizedRequest,
    test_case: TestCase,
    *,
    profile: ScannerProfile,
) -> NormalizedRequest:
    """Route to the profile-specific mutation builder behind one shared entry point."""

    if profile == ScannerProfile.CTF:
        return build_ctf_test_request(baseline, test_case)
    return build_safe_test_request(baseline, test_case)
