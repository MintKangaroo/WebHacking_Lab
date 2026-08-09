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
- Every execution attempt, including blocked attempts, produces an audit
  event.

Phase 3 implements controlled target execution for `GET`, `HEAD`, and `OPTIONS`
only. It sends no body or persisted credentials, binds approval to the exact
redacted request revision, pins the socket connection to approved DNS answers,
revalidates every redirect, and stores only redacted responses. One approval
permits at most five requests including redirects.

Phase 8 adds a cancellable Passive URL Scanner. Creating a job requires the
literal `START PASSIVE SCAN` confirmation, an authorized purpose, a registered
Scope, an execution-enabled workspace, and remaining request budget. The job
uses the same request gateway for every page and redirect; it cannot switch to
an active profile after creation.

Phase 9 adds a separate `SAFE` job profile. It finishes passive collection,
persists exact low-risk request previews, and stops in `Waiting for Approval`.
Only selected preview IDs can move to execution, every row is limited to one
GET or OPTIONS request, and the shared gateway rechecks server mode, workspace,
Scope, DNS/IP, rate, budget, timeout, size, and redaction. Unselected previews
remain unsent. SQL extraction, timing delays, executable XSS, writes, command
execution, credentials, and request bodies are denied.

External targets remain disabled until both process switches are explicitly
enabled, an authorization-backed project scope exists, the workspace is
enabled with a stated purpose, and the exact request preview is confirmed.

## Current execution limits

- State-changing methods and request bodies are blocked.
- Redacted query fields, cookies, authorization, API keys, and non-allowlisted
  headers are omitted rather than replayed.
- TLS verification is always enabled in the controlled client; environment
  proxies and insecure TLS options are ignored.
- HTTPS-to-HTTP redirect downgrades are blocked.
- Scope checks return all approved IPs and the transport connects only to those
  addresses while retaining the original hostname for TLS SNI.
- Global and per-target rolling-minute limits, target concurrency, workspace
  budget, timeout, maximum response bytes, and redirect count are enforced.
- Passive analyzers and active plugins can propose bounded tests but cannot call the client.
- Passive Scanner requests are sequential GETs. Browser JavaScript, form
  submission, login automation, active mutation, downloads, and OpenAPI path
  template execution are disabled.
- Crawl depth, pages, total requests, pacing, inventory size, logout handling,
  and response bytes are bounded. A cancellation flag is checked between each
  request.
- Discovered query secrets are masked in inventory and omitted by the request
  gateway. Parser output cannot introduce a new origin outside registered Scope.
- SAFE mutation is centralized: secret-shaped parameters, destructive flags,
  multi-request cases, medium/high risk, modifying SQL keywords, comments,
  semicolons, and unsupported mutation types are rejected.
- SAFE redirect observations do not follow `Location`; they store the first
  redacted response so an external marker cannot become an outbound request.

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
