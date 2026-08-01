# Security policy

## Intended use

WebHacking Lab is for systems the user owns or is explicitly authorized to
test, CTF targets, and isolated local labs. Authorization and scope are
workspace data and will be enforced by code, not accepted as a banner-only
promise.

## Secure defaults

- Application mode starts as **Analysis Only**.
- Network execution starts disabled and requires workspace-level activation.
- Insecure TLS is disabled in production.
- Request rate, per-target concurrency, timeout, and response size are bounded.
- No request is executed automatically from an analyzer result.
- Sensitive headers and cookies must be redacted at ingestion and again on
  export.
- Every future execution attempt, including blocked attempts, produces an audit
  event.

Phase 2 implements these configuration defaults together with project scope,
DNS/IP decisions, cURL/HAR ingestion, structured redaction, and append-only
audit events. Target HTTP execution itself is not present yet.

## Dependency advisory note

The current React Router release reports an upstream high-severity advisory for
React Server Components action handling. This application is a client-only
Vite SPA: it does not enable React Router framework/RSC mode, server actions, or
action routes, so the affected execution path is absent. The dependency remains
pinned to the newest published release and should be upgraded as soon as an
upstream patched version is available. CI security checks must not silently
ignore this advisory.

## Non-negotiable implementation rules

Feature packages must not bypass the shared guarded HTTP client. A URL scanner,
active plugin, repeater action, source-generated request, and PoC verification
all use the same Scope Guard, DNS/IP/redirect policy, rate limiter, budgets,
response limits, redaction, and audit sink.

Uploaded code is data. The service does not execute it, import it, install its
dependencies, or use user-controlled paths directly.

Production code must not add reverse shells, persistent backdoors, credential
harvesting, session theft, malware delivery, destructive SQL, arbitrary file
overwrite, denial-of-service logic, mass brute force, network-range scanning,
lateral movement, or cloud metadata credential extraction.

## Reporting a vulnerability

Do not open a public issue containing an exploitable vulnerability or secret.
Contact the repository owner privately with affected versions, reproduction
conditions, impact, and a minimal non-destructive demonstration. Remove real
credentials, session tokens, and target data.

## Secret handling

Do not commit `.env`, databases, captured requests, source uploads, reports, or
artifacts. The repository ignore rules cover standard local locations, but
contributors remain responsible for reviewing staged changes.
