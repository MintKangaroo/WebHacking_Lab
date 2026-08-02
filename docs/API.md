# API guide

기본 경로는 `/api`이며 실행 중인 앱의 `/api/docs`가 최종 OpenAPI 계약입니다. 오류는 `code`, `message`, `correlation_id`를 반환합니다.

## 안전한 외부 요청 순서

1. `POST /projects/{project_id}/scope`로 권한 확인과 범위를 등록합니다.
2. `POST /projects/{project_id}/scope/check`로 전송 없이 URL 정책을 확인합니다.
3. `POST /workspaces/{workspace_id}/execution/enable`로 워크스페이스를 승인합니다.
4. `POST /requests` 또는 import API로 redacted 요청을 저장합니다.
5. `POST /requests/{request_id}/execute/preview`로 정확한 요청과 approval token을 받습니다.
6. `POST /requests/{request_id}/execute`에 token, request version, 확인 문구를 보냅니다.

워크스페이스 승인 예시:

```json
{
  "authorization_confirmed": true,
  "confirmation_phrase": "ENABLE CONTROLLED REQUESTS",
  "expected_use": "Authorized read-only assessment of the registered endpoint",
  "version": 1
}
```

요청별 승인 예시:

```json
{
  "confirmation_phrase": "SEND UP TO 5 SAFE REQUESTS",
  "approval_token": "<64-character token returned by preview>",
  "request_version": 1
}
```

Approval token은 요청 revision, 워크스페이스 revision, Scope rule, 정확한 전송 내용을 묶습니다. 상태가 바뀌면 preview를 다시 받아야 합니다.

Preview에는 승인 1회당 최대 요청 수와 요청별 최대 응답 바이트가 포함됩니다. 실제 스트리밍 계층은 서버 전역 상한과 호출 기능의 더 작은 상한 중 작은 값을 사용합니다.

## Passive URL Scanner

Scanner는 별도 네트워크 경로를 만들지 않습니다. 프로젝트 Scope와 워크스페이스 실행 승인을 마친 뒤 다음처럼 명시적인 bounded plan을 제출합니다.

```http
POST /api/scans
Content-Type: application/json

{
  "project_id": "<uuid>",
  "workspace_id": "<uuid>",
  "target": "https://authorized.example/review/",
  "profile": "passive",
  "crawl_policy": {
    "max_depth": 2,
    "max_pages": 20,
    "max_requests": 30,
    "max_response_bytes": 2000000,
    "requests_per_second": 1,
    "concurrency": 1,
    "include_subdomains": false,
    "respect_logout_routes": true,
    "execute_javascript": false
  },
  "authorization_confirmed": true,
  "confirmation_phrase": "START PASSIVE SCAN",
  "expected_use": "Authorized passive application inventory"
}
```

`202 Accepted` 이후 다음 endpoint를 polling할 수 있습니다.

```text
GET  /api/scans?project_id=<uuid>
GET  /api/scans/{scan_id}
GET  /api/scans/{scan_id}/events
GET  /api/scans/{scan_id}/endpoints
GET  /api/scans/{scan_id}/parameters
GET  /api/scans/{scan_id}/findings
POST /api/scans/{scan_id}/cancel
```

현재 서버가 허용하는 프로필은 `passive`뿐입니다. `safe`, `ctf`, `local_lab`은 구현되지 않은 active 기능으로 간주해 `403 execution_blocked`로 종료합니다. `execute_javascript=true`도 허용하지 않습니다. 외부 호스트는 권한 확인이 저장된 Scope 안에 있어야 하며 모든 redirect는 다시 검사됩니다.

## 분석

```http
POST /api/analysis
Content-Type: application/json

{
  "request_id": "<uuid>",
  "response_id": "<optional uuid>"
}
```

응답은 6개 `AnalysisResult`와 React Flow용 `nodes`, `edges`를 포함합니다. 이 endpoint는 네트워크 요청을 생성하지 않습니다.

```http
POST /api/diff
Content-Type: application/json

{
  "baseline_response_id": "<uuid>",
  "test_response_id": "<uuid>",
  "ignore_patterns": [],
  "jsonpath_ignore": ["$.csrf"],
  "css_selector_ignore": [".timestamp"]
}
```

Diff는 status, multivalue header, cookie, body similarity, JSON path, HTML text, size, elapsed time, redirect와 새 오류 패턴을 비교합니다.

## 정책 오류

| HTTP | code | 의미 |
| --- | --- | --- |
| 403 | `execution_blocked` | 전역/워크스페이스/메서드/Scope 정책 차단 |
| 409 | `conflict` | preview 또는 entity version이 오래됨 |
| 413 | `response_too_large` | 응답 상한 초과 |
| 429 | `rate_limited` | 전역/대상 rate 또는 concurrency 초과 |
| 502 | `upstream_request_failed` | timeout, TLS, 연결 오류 등 안전한 upstream 실패 |

실제 비밀값이나 upstream 내부 예외는 오류 응답과 감사 로그에 포함하지 않습니다.
