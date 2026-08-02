# Threat model

## Assets

- Testing authorization and allowlisted scope
- Captured HTTP requests, responses, and evidence
- Session profiles and encrypted secret values
- Uploaded source archives and derived indexes
- Findings, reports, audit events, and local lab state
- Host, container, and internal network integrity

## Trust boundaries

1. Browser to FastAPI API
2. API feature services to the guarded execution gateway
3. Guarded client to an allowlisted target
4. Redirect and DNS resolution back into scope validation
5. Untrusted archive to isolated artifact storage
6. Main application network to the internal lab network
7. Persisted records to report exports

## Principal threats and controls

| Threat | Required control |
| --- | --- |
| SSRF through a target URL | HTTP(S)-only parser, no userinfo, DNS/IP policy, scope allowlist |
| Redirect scope escape | Full validation on every redirect hop |
| DNS rebinding | Validate all answers and pin the approved address per attempt |
| Metadata access | Explicit metadata ranges/hostnames deny policy |
| Excessive traffic | Global rate, sequential scanner, target concurrency, job budget, cancellation |
| Destructive mutation | Non-destructive test model and profile policy |
| Secret leakage | Structured allowlist logging, field redaction, export redaction |
| ZIP Slip / archive bomb | Canonical containment and extraction budgets |
| Uploaded-code execution | No import/build/run/dependency-install path |
| Lab breakout | Internal network, non-root, dropped capabilities, limits, read-only FS |
| Analyzer overclaim | Evidence, confidence, validation state, and limitations |
| Execution bypass | One guarded client injected into all execution-capable services |
| UI approval confusion | Exact request/impact/count preview and explicit confirmation |
| Stored credential replay | Omit redacted queries, cookies, authorization, and API keys |
| Redirect amplification | Per-execution five-request ceiling and scan budget/rate check before every hop |
| Crawl queue explosion | Depth/page/request/inventory ceilings, deduplication, same-origin policy |
| Secret replay from discovered URL | Redact stored sample and omit sensitive query values before execution |
| OpenAPI template execution | Record `{parameter}` paths in inventory but never enqueue them |
| Oversized scan response | Enforce the smaller job/global byte ceiling while streaming |
| TLS interception | System trust validation, original SNI, no insecure override |

## Abuse cases

- A user supplies a public URL that redirects to `169.254.169.254`.
- A scoped hostname resolves to a public address during validation and a private
  address during connection.
- A crawler discovers a logout link, an infinite calendar, or a large file.
- An analyzer proposes `DROP`, file write, command execution, or an excessive
  time delay.
- A CTF profile is selected for a production host.
- A ZIP entry escapes extraction, is a symbolic link, or expands beyond budget.
- Source-generated tests attempt to infer an unregistered hostname.
- A report embeds an authorization header captured before redaction.

Each case requires a regression test before the related feature is considered
complete.

Current regression tests use fake external DNS/transports or loopback servers;
the test suite never calls an external target.

## Residual risk

Static analysis is incomplete, runtime signals can be noisy, authorization
claims may be false, DNS and network conditions change, and isolated labs may
contain implementation mistakes. The product reduces these risks through
bounded capability, explicit user decisions, auditability, and conservative
status language; it cannot eliminate them.
