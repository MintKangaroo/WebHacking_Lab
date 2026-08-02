# WebHacking Lab

CTF, 로컬 랩, 명시적으로 허가받은 모의해킹의 HTTP 증거를 한곳에서 분석하는 안전 중심 웹 보안 워크스페이스입니다.

요청·응답 정규화, 민감정보 마스킹, Scope 관리, 제한적 외부 요청, 응답 Diff, 6개 수동 분석기, React Flow 분석 흐름과 **안전한 Passive URL Scanner**가 실제 FastAPI 데이터로 동작합니다.

> 기본값은 **Analysis Only**입니다. 외부 요청은 서버 설정, 프로젝트 Scope, 권한 확인, 워크스페이스 승인, 요청별 최종 확인을 모두 통과해야 합니다.

![WebHacking Lab 대시보드](docs/screenshots/dashboard.png)

| 외부 Scope와 실행 승인 | Repeater와 정확한 요청 확인 |
| --- | --- |
| ![Scope와 실행 승인](docs/screenshots/project-scope.png) | ![HTTP Repeater](docs/screenshots/http-repeater.png) |

| 수동 분석 결과 | React Flow 분석 흐름 |
| --- | --- |
| ![수동 분석 결과](docs/screenshots/analysis-results.png) | ![분석 흐름](docs/screenshots/analysis-flow.png) |

![Scope 기반 Passive URL Scanner](docs/screenshots/url-scanner.png)

## 빠른 시작

Docker와 Docker Compose v2만 있으면 됩니다.

```bash
git clone https://github.com/MintKangaroo/WebHacking_Lab.git
cd WebHacking_Lab
cp .env.example .env
docker compose up --build
```

- 앱: <http://localhost:8080>
- API 문서: <http://localhost:8080/api/docs>
- 상태 확인: <http://localhost:8080/api/health>

종료:

```bash
docker compose down
```

포트가 겹치면 `.env`의 `WEBHACKING_FRONTEND_PORT=28080`만 변경하세요.

## 가장 쉬운 사용법

### 1. 요청을 보내지 않고 분석하기

1. **Projects**에서 프로젝트를 만듭니다.
2. **HTTP Repeater**에서 cURL 또는 HAR를 붙여넣습니다.
3. 미리보기만 필요하면 **Import safely**를 누릅니다.
4. 분석 기록을 남기려면 **Save for analysis**를 켜고 프로젝트와 워크스페이스를 고릅니다.
5. **Run 6 analyzers**로 Security Header, CORS, JWT, XSS reflection, SQL error indicator, Cookie 설정을 확인합니다.
6. 응답이 2개 이상이면 **Compare last 2**로 상태·헤더·JSON·HTML·크기·시간·에러 패턴을 비교합니다.

예제:

```bash
curl 'http://127.0.0.1:5000/search?q=demo' \
  -H 'Authorization: Bearer demo-token'
```

cURL은 명령으로 실행되지 않고 데이터로만 파싱됩니다. `Authorization`, Cookie, API Key, 토큰 계열 값은 저장 전에 `[REDACTED]` 처리됩니다.

### 2. 허가받은 외부 호스트에 제한적으로 요청하기

먼저 `.env`에서 두 값을 명시적으로 바꾼 뒤 앱을 다시 빌드합니다.

```dotenv
WEBHACKING_ANALYSIS_ONLY=false
WEBHACKING_NETWORK_EXECUTION_ENABLED=true
```

```bash
docker compose up --build
```

그다음 UI에서 다음 순서로 진행합니다.

1. **Projects**에서 `Authorized Pentest` 또는 `CTF` 프로젝트를 만듭니다.
2. **Register external host**에 `scheme`, `hostname`, 선택적 `port`, `path`를 입력합니다.
3. 권한과 범위를 설명하고 소유권/테스트 권한 확인란을 선택합니다.
4. **Controlled request approval**에 사용 목적을 적고 워크스페이스 실행을 활성화합니다.
5. Repeater에서 `GET`, `HEAD`, `OPTIONS` 요청을 저장합니다.
6. **Review exact request**로 실제 전송될 요청, Scope 결과, 최대 요청 수, 예상 영향을 확인합니다.
7. 최종 확인란을 선택한 뒤 **Send controlled request**를 누릅니다.

현재 외부 실행은 다음 경계를 강제합니다.

- `GET`, `HEAD`, `OPTIONS`만 허용하고 body는 전송하지 않음
- 저장된 Authorization, Cookie, API Key와 민감 Query 값을 재전송하지 않음
- 실제 연결을 Scope Guard가 승인한 DNS IP에 고정
- 리다이렉트마다 scheme, host, port, path, DNS/IP, Scope를 다시 확인
- HTTPS에서 HTTP로 내려가는 리다이렉트 차단
- 승인 1회당 최대 5개 요청, 전역/대상별 rate limit과 동시성 제한
- 워크스페이스 요청 예산, timeout, 요청별 최대 응답 크기 적용
- TLS 인증서 검증을 항상 사용하고 환경 proxy를 사용하지 않음
- 성공·실패·정책 차단을 감사 로그에 기록

공격 페이로드 실행, 로그인 brute force, 데이터 추출, 파일 쓰기, 명령 실행은 제공하지 않습니다.

### 3. URL을 안전하게 자동 탐색하기

외부 호스트도 사용할 수 있지만, 반드시 위의 **외부 Scope 등록**과 **워크스페이스 실행 승인**을 먼저 완료해야 합니다.

1. 좌측 **URL Scanner**를 엽니다.
2. 실행 승인이 끝난 프로젝트와 워크스페이스를 선택합니다.
3. 등록된 Scope 안의 시작 URL을 입력합니다.
4. Depth, Pages, Requests, 초당 요청 수를 확인합니다. 처음에는 `Depth 2 / Pages 20 / Requests 30 / 1 req/s`를 권장합니다. 실제 속도는 Scope와 전역 분당 한도 중 더 낮은 값으로 자동 조정됩니다.
5. 승인된 사용 목적을 적고 권한 확인란을 선택합니다.
6. **Start passive scan**을 누릅니다.
7. 실시간으로 Endpoint, Parameter, Passive Finding, Policy Event를 확인합니다. 필요하면 **Stop scan**으로 중단합니다.

Scanner가 자동으로 확인하는 범위:

- HTML link, form, iframe, script source
- 정적 JavaScript의 `fetch`, Axios, XMLHttpRequest, WebSocket URL 문자열
- `robots.txt`, `sitemap.xml`, OpenAPI/Swagger 문서
- Query, Form, JSON, Multipart parameter inventory
- 서버/프레임워크 단서, Security Header, CORS, Cookie, JWT, XSS 반사, SQL 오류 지표

현재 Scanner는 `PASSIVE` 프로필만 실행합니다. GET 기반 문서 수집만 수행하고, JavaScript 실행·로그인 자동화·파라미터 변형·취약점 payload·active test는 만들거나 보내지 않습니다. 발견한 OpenAPI 경로 템플릿은 Inventory에는 기록하지만 실제 URL로 요청하지 않습니다.

## 현재 기능

- 프로젝트, 워크스페이스, 요청 예산, optimistic locking
- loopback 기본 Scope와 권한 확인이 필요한 외부 Scope
- SSRF 방지 URL/DNS/IP/metadata/link-local 정책
- DNS-pinned HTTPX 클라이언트와 리다이렉트 재검사
- cURL/HAR 가져오기, Raw/구조화 HTTP 정규화, multimap 보존
- 헤더·Cookie·Query·JSON/Form 본문·감사 로그 마스킹
- 요청 Revision, 응답 증거, 감사 이벤트 저장
- UUID/timestamp/nonce/CSRF 노이즈를 줄이는 Response Diff
- JSON path ignore, CSS selector ignore, 사용자 정규식 ignore
- 6개 passive analyzer와 `Observation / Suspicious / Likely / Not Tested` 구분
- 실행되지 않은 안전 테스트 제안과 분석 한계 표시
- React Flow 분석 그래프와 노드 Inspector
- 취소 가능한 Passive Scan Job과 실시간 진행률·요청 예산
- HTML/JS/robots/sitemap/OpenAPI 기반 Endpoint·Parameter Inventory
- 기존 6개 분석기를 재사용하는 URL별 Passive Finding
- 스캔 응답 크기 제한을 스트리밍 다운로드 단계에서 강제
- SQLite 기본, PostgreSQL 선택 지원, Alembic migration
- non-root/read-only Docker 런타임과 GitHub Actions

분석기는 수동 증거만으로 취약점을 확정하지 않습니다. `Confirmed`는 별도의 재현 증거와 검토가 필요한 상태입니다.

## 아키텍처

```mermaid
flowchart TD
    UI[React Dashboard] --> API[FastAPI Application]
    API --> SG[Scope Guard]
    API --> HC[DNS-pinned HTTP Client]
    API --> AN[Passive Analysis Engine]
    API --> SC[Passive URL Scanner]
    API --> DF[Diff Engine]
    API --> AU[Audit Log]
    API --> DB[(SQLite / PostgreSQL)]
    SG --> RL[Rate + Concurrency + Budget]
    RL --> HC
    SC --> RL
    HC --> RG[Redirect Revalidation]
    RG --> RD[Response Limit + Redaction]
    RD --> DB
    API -. future .-> LAB[Isolated Local Labs]
```

```mermaid
flowchart LR
    IN[cURL / HAR / Form] --> N[Normalize]
    N --> R[Redact]
    R --> P[Passive Analysis]
    P --> H[Hypotheses]
    H --> U[User Review]
    U --> S[Scope + Approval]
    S --> X[Controlled Request]
    X --> D[Response Diff]
    D --> E[Evidence]
```

실행 가능한 모든 기능은 하나의 Scope Guard, Rate Limit, Redaction, Audit 경로를 사용합니다. 자세한 설계는 [ARCHITECTURE.md](docs/ARCHITECTURE.md), [SECURITY.md](docs/SECURITY.md), [THREAT_MODEL.md](docs/THREAT_MODEL.md)를 참고하세요.

## 주요 API

```text
POST   /api/projects
POST   /api/projects/{project_id}/scope
POST   /api/projects/{project_id}/scope/check
POST   /api/workspaces/{workspace_id}/execution/enable
POST   /api/workspaces/{workspace_id}/execution/disable
POST   /api/requests/import/curl
POST   /api/requests/import/har
POST   /api/requests
POST   /api/requests/{request_id}/execute/preview
POST   /api/requests/{request_id}/execute
POST   /api/diff
POST   /api/analysis
GET    /api/analysis/{analysis_id}
GET    /api/analysis/{analysis_id}/flow
POST   /api/scans
GET    /api/scans
GET    /api/scans/{scan_id}
POST   /api/scans/{scan_id}/cancel
GET    /api/scans/{scan_id}/endpoints
GET    /api/scans/{scan_id}/parameters
GET    /api/scans/{scan_id}/findings
GET    /api/scans/{scan_id}/events
GET    /api/audit-events
```

전체 계약과 예시는 `/api/docs`에서 확인할 수 있습니다. 요약은 [API.md](docs/API.md)에 있습니다.

## 로컬 개발과 테스트

Python 3.12 이상, Node.js 20 이상을 사용합니다.

```bash
make bootstrap
make backend-dev
```

새 터미널:

```bash
make frontend-dev
```

전체 품질 확인:

```bash
# Backend: Ruff, format, mypy strict, pytest + 85% coverage
docker build --target test -f backend/Dockerfile .

# Frontend: ESLint, strict TypeScript, Vitest coverage, production build
cd frontend
npm ci
npm run lint
npm run typecheck
npm run test
npm run build

# Docker 앱 E2E
npx playwright install chromium
PLAYWRIGHT_BASE_URL=http://127.0.0.1:8080 npm run e2e
```

현재 Backend 81개, Frontend 9개 unit/integration, Playwright 핵심 E2E를 포함합니다. 자동 테스트는 실제 외부 서비스에 요청하지 않습니다.

## 환경 변수

| 변수 | 기본값 | 의미 |
| --- | --- | --- |
| `WEBHACKING_ANALYSIS_ONLY` | `true` | 전역 분석 전용 모드 |
| `WEBHACKING_NETWORK_EXECUTION_ENABLED` | `false` | 전역 네트워크 실행 스위치 |
| `WEBHACKING_ALLOW_INSECURE_TLS` | `false` | 현재 외부 클라이언트에서는 사용하지 않음; TLS 검증 고정 |
| `WEBHACKING_GLOBAL_REQUESTS_PER_MINUTE` | `30` | 프로세스 전역 요청 한도 |
| `WEBHACKING_DEFAULT_TARGET_CONCURRENCY` | `2` | 기본 동시성 상한 |
| `WEBHACKING_REQUEST_TIMEOUT_SECONDS` | `10` | 요청 timeout |
| `WEBHACKING_MAX_REQUEST_BYTES` | `1048576` | 저장 요청 body 상한 |
| `WEBHACKING_MAX_RESPONSE_BYTES` | `2097152` | 스트리밍 다운로드 응답 상한 |
| `WEBHACKING_MAX_HAR_BYTES` | `10485760` | HAR 입력 상한 |

전체 예시는 [.env.example](.env.example)에 있습니다.

## 안전·윤리 원칙

이 프로젝트는 사용자가 소유하거나 명시적인 허가를 받은 시스템, CTF, 로컬 랩에서만 사용해야 합니다.

인터넷 대역 스캔, 자동 exploit, credential harvesting, phishing, session hijacking, malware, reverse shell, persistent backdoor, destructive SQL, arbitrary file overwrite, DoS, 대량 brute force, lateral movement, cloud metadata credential extraction은 구현하지 않습니다.

## 현재 제한과 로드맵

현재 구현 범위는 Foundation, HTTP Workspace, 제한적 외부 Repeater, Diff, Passive Analysis, React Flow 기초, Phase 8 Passive URL Scanner입니다.

- URL crawler는 Passive 프로필만 지원하며 SAFE/CTF/LOCAL_LAB active test plan과 개별 승인은 후속 Phase입니다.
- Source ZIP 업로드와 AST taint analysis는 아직 없습니다.
- CTF Workspace, Encoding Workbench, 5개 격리 Lab, Finding/Report는 후속 Phase입니다.
- 저장된 인증정보는 의도적으로 실행에 재사용하지 않아 로그인 세션 크롤링은 지원하지 않습니다.
- 프로세스 내 rate limiter는 단일 인스턴스 기준이며 다중 replica 전역 한도는 향후 공유 저장소가 필요합니다.
- 분석 결과는 완전성을 보장하지 않으며 증거·신뢰도·한계를 함께 해석해야 합니다.

## 기여와 라이선스

Conventional Commits와 작은 변경 단위를 사용합니다. 실행 경계를 바꿀 때는 abuse-case 회귀 테스트와 문서를 함께 갱신해 주세요. Scope Guard, Redaction, Rate Limit, Audit 경로를 우회하는 기능은 받지 않습니다.

[MIT License](LICENSE)
