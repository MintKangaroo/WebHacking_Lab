# PHASE 1 — 인벤토리

> 이 문서는 인벤토리 단계만 다룬다. 심층 감사(PHASE 2)와 통합 리포트(PHASE 3)는 이후 단계에서 작성한다.

---

## 0. 최우선 결론 — 감사 전제와 저장소 실체의 불일치

**이 저장소는 "다수의 의도적 취약 챌린지 세트"가 아니다.** 감사 지시문은
SQLi/XSS/SSRF 등을 심어 둔 CTF 챌린지 랩을 전제하고 "죽은 취약점 / 의도치
않은 해법 / 플래그 유출 / 채점 우회"를 찾으라고 요구하지만, 실제 코드에는
**의도적으로 취약한 챌린지, 플래그, 채점 로직이 존재하지 않는다.**

실체는 **통제형(방어지향) 웹 보안 분석 도구 플랫폼**이다. 즉 "취약한 표적"이
아니라 "표적을 분석하는 도구"다. 근거:

- 앱 설명 자체가 분석 도구임을 명시: `backend/webhacking_lab/api/app.py:64-67`
  ("Safety-first analysis API ... Network execution is disabled by default.")
- 기본값이 실행 차단: `analysis_only=True`, `network_execution_enabled=False`
  (`backend/webhacking_lab/core/config.py:30-31`)
- 랩(취약 서비스)은 **미구현**이며 Phase 6 예정: `labs/README.md:1-5`
  ("Local training services are added in Phase 6"). `docker-compose.yml:73-77`의
  `isolated_labs` 네트워크는 정의만 되어 있고 붙는 서비스가 없다.
- 저장소에 취약앱 소스, 플래그 문자열, 챌린지 디렉터리, 채점기가 없다
  (뒤 §3 커버리지 매트릭스 참조).
- README 로드맵도 동일하게 확인: "CTF Workspace ... 5개 격리 Lab ... 은
  후속 Phase" (`README.md:343`).

**결과적으로 PHASE 2의 A(익스플로잇 가능성), B(의도치 않은 해법), D(플래그·채점),
E(난이도·학습 가치)는 감사 대상 산출물이 아직 존재하지 않으므로 적용 불가다.**
대신 이 코드베이스에서 실질적 감사 가치가 있는 축은 다음이다:

1. **C(격리·안전성)** — 이 도구는 아웃바운드 요청/능동 프로브를 보낼 수 있는
   공격 능력을 갖는다. SSRF 가드, DNS 핀, 리다이렉트 재검사, CTF 무인 실행
   모드가 실제로 경계를 지키는가가 핵심 감사 대상이다.
2. **F(재현성·운영)** / **G(코드 건전성)** — 파일 업로드(코드 분석) 경로의
   ZIP-slip/링크/자원 한도, 레이트리밋·예산의 실제 강제, 크래시 지점.
3. 별도로: **정적/능동 분석기가 실제로 탐지 대상을 탐지하는가**(도구로서의
   기능 정합성) — CTF 랩의 "죽은 취약점"에 대응하는, 이 도구에서의
   "죽은 탐지 규칙"을 찾는 관점.

PHASE 2는 위 관점으로 재정의해서 진행할 것을 권한다. 확증 전까지 이 재정의
자체는 사용자 승인이 필요할 수 있어 **UNVERIFIED-SCOPE**로 표시한다.

---

## 1. 랩 구조

**단일 애플리케이션(모놀리식 도구), 다수 챌린지 아님.**

- 백엔드: FastAPI (Python 3.12), `backend/webhacking_lab/`
- 프런트엔드: React + Vite + TypeScript, `frontend/src/`
- 배포: Docker Compose 2개 서비스(backend, frontend/nginx),
  `docker-compose.yml`
- 저장소: SQLite 기본, PostgreSQL 선택, Alembic 마이그레이션
  (`config.py:25`, `README.md:187`)

기능 모듈(백엔드):

| 모듈 | 경로 | 역할 |
| --- | --- | --- |
| API 라우터 | `api/routers/{system,projects,http_requests,analysis,scans,code_projects,audit}.py` | 7개 라우터, `/api` 프리픽스 (`api/app.py:113-119`) |
| HTTP 클라이언트 | `http_client/{client,scope_guard,request_normalizer}.py` | DNS-핀 HTTPX, SSRF 스코프 가드 |
| 스캐너 | `scanner/{engine,active_engine,execution_policy,jobs,crawler,...}.py` | PASSIVE/SAFE/CTF URL 스캔 |
| 정적 분석 | `static_analysis/{taint_engine,archive,route_extractor,...}.py` | 실행 없는 Python/PHP 소스→싱크 |
| 수동 분석기 | `analyzers/{header,cors,jwt,xss,injection,auth}_analyzer.py` | 6개 passive 분석기 |
| 코어 | `core/{config,redaction,rate_limit,logging}.py` | 설정·마스킹·레이트리밋 |

---

## 2. 엔드포인트 / 기능별 인벤토리

챌린지가 아니라 **도구 기능**이므로, 각 엔드포인트의 "의도한 취약점"이 아니라
"기능과 안전 경계"를 기록한다. (엔드포인트 목록 근거: `README.md:235-269`,
라우터 구성 `api/app.py:113-119`)

| 엔드포인트(요약) | 기능 | 안전 경계 / 감사 관심사 |
| --- | --- | --- |
| `POST /api/projects`, `/scope`, `/scope/check` | 프로젝트·스코프 규칙 등록/검사 | 스코프 규칙 매칭 로직(`scope_guard.py:70-86`) |
| `POST /api/workspaces/{id}/execution/enable|disable` | 워크스페이스별 실행 승인 | 실행 게이트 |
| `POST /api/requests/import/{curl,har}` | cURL/HAR를 **데이터로만** 파싱 | 실행 아님, 마스킹(`README.md:66`) |
| `POST /api/requests/{id}/execute[/preview]` | 통제형 아웃바운드 요청 | GET/HEAD/OPTIONS 한정, 스코프+승인+DNS핀 |
| `POST /api/diff`, `/api/analysis` | 응답 Diff, 6개 수동 분석기 | 순수 분석, 네트워크 없음 |
| `POST /api/scans` + 하위 GET/approve | PASSIVE/SAFE/CTF URL 스캐너 | **최고 위험**: 능동 프로브, CTF 무인 실행 |
| `POST /api/code-projects/upload` + 분석 | 소스 ZIP/파일 업로드→정적 분석 | **파일 업로드 안전성**: ZIP slip/링크/한도(`static_analysis/archive.py`) |
| `GET /api/audit-events` | 감사 로그 조회 | 로그에 플래그/시크릿/페이로드 과다 노출 여부 |

**실행 3단계 게이트**(모든 아웃바운드 공통, `README.md:91-102`, `config.py:30-32`):
전역 스위치(`analysis_only`/`network_execution_enabled`) → 프로젝트 Scope 등록
→ 워크스페이스 실행 승인 → 요청별 최종 확인. **CTF 프로필은 이 게이트 중
인가·승인 절차만 완화**하고 SSRF/마스킹/레이트리밋/감사는 유지한다고 주장
(`README.md:132-142`) — PHASE 2에서 코드로 확증 필요.

---

## 3. 취약점 커버리지 매트릭스

두 층위로 나눈다. (a) **의도적 취약 실습 표적**으로서의 커버리지, (b) 도구가
가진 **탐지/분석 규칙**으로서의 커버리지.

### (a) 의도적 취약 실습 표적 — **전 축 공백**

| 축 | 실습 취약 표적 존재? | 근거 |
| --- | --- | --- |
| SQLi / NoSQLi | ❌ 없음 | 취약앱/DB 챌린지 부재; `labs/` 미구현(`labs/README.md`) |
| XSS(reflected/stored/DOM) | ❌ 없음 | 동일 |
| CSRF | ❌ 없음 | 동일 |
| SSRF | ❌ 없음(표적) | 단, 도구 자체의 SSRF **방어**는 존재(§3b) |
| SSTI | ❌ 없음 | 동일 |
| 역직렬화 | ❌ 없음 | 동일 |
| 커맨드 인젝션 | ❌ 없음 | 동일 |
| 파일 업로드 | ❌ 표적 없음 | 단, 도구의 업로드 **수용** 경로 존재(§4 위험면) |
| LFI / RFI | ❌ 없음 | 동일 |
| IDOR / 접근통제 | ❌ 없음 | 동일 |
| 인증·세션(JWT) | ❌ 표적 없음 | 단, JWT **분석기**는 존재(§3b) |
| 레이스컨디션 | ❌ 없음 | 동일 |
| XXE | ❌ 없음 | 동일 |
| GraphQL | ❌ 없음 | 동일 |
| 비즈니스 로직 | ❌ 없음 | 동일 |

→ **실습 표적 관점에서는 16개 축 전부 공백.** 이는 "커버리지 갭"이 아니라
설계상 아직 그 단계(Phase 6)에 도달하지 않은 것으로 보인다.

### (b) 도구의 탐지/분석 규칙 커버리지

| 축 | 탐지 규칙 존재? | 근거(확증은 PHASE 2) |
| --- | --- | --- |
| SQLi | 부분(오류/boolean/UNION 프로브) | `scanner/execution_policy.py:22-32` CTF 뮤테이션, SAFE 플러그인 |
| XSS(reflected) | 부분(inert marker 반사) | `execution_policy.py:26`, `analyzers/xss_analyzer.py` |
| SSRF **방어** | 있음 | `http_client/scope_guard.py:89-102`(metadata/link-local/reserved 차단) |
| Path traversal | 부분(CTF `/etc/passwd` 프로브) | `execution_policy.py:28`(`ctf_path_traversal`) |
| Open redirect | 부분(예약 도메인) | `execution_policy.py:30` |
| CORS | 있음(수동 분석기) | `analyzers/cors_analyzer.py` |
| JWT | 있음(수동 분석기) | `analyzers/jwt_analyzer.py` |
| Security header/Cookie | 있음 | `analyzers/header_analyzer.py` |
| 정적 taint(Python Flask/PHP) | 있음(보수적) | `static_analysis/taint_engine.py`, `README.md:157` |
| NoSQLi/SSTI/역직렬화/XXE/GraphQL/CSRF/IDOR/레이스 | ❌ 탐지 규칙 없음 | 스캐너/분석기 목록에 부재 |

→ 도구 기능으로서도 다수 축(SSTI, 역직렬화, XXE, GraphQL, IDOR, 레이스,
CSRF 능동탐지)이 미구현. 단 이는 도구 로드맵 문제이지 "죽은 취약점"과는 다름.

---

## 4. 실행/배포 방식 및 격리

- **단일 명령 기동**: `docker compose up --build` (`README.md:29-34`) — 0→기동
  단일 명령 존재.
- **컨테이너 하드닝**(감사상 긍정 신호, 다만 칭찬 아님·사실 기록):
  - `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true`
    (backend `docker-compose.yml:19-25`, frontend `:49-61`)
  - backend 데이터는 named volume, `/tmp`만 tmpfs
- **포트 노출**: frontend만 호스트에 `${WEBHACKING_FRONTEND_PORT:-8080}:8080`
  바인딩(`docker-compose.yml:45-46`). backend는 호스트 노출 없음(내부
  `application` 네트워크). **단, 컨테이너 내부 API 바인딩은
  `api_host="0.0.0.0"`**(`config.py:23`) — compose상 backend 포트 미매핑이라
  현재는 호스트 노출 안 됨. PHASE 2에서 우회 노출 경로 확인 필요.
- **격리 네트워크**: `isolated_labs`는 `internal: true`로 정의되나 소비 서비스
  없음(`docker-compose.yml:73-77`, `labs/README.md`).
- **위험면 요약**(PHASE 2 심층 대상):
  1. 스캐너 CTF 프로필 무인 실행 — 능동 프로브가 스코프/SSRF 가드를 정말
     못 벗어나는가.
  2. 코드 업로드 — ZIP slip/심링크/자원고갈(`static_analysis/archive.py`,
     217행).
  3. DNS 리바인딩 — 스코프 검사 시점 IP와 실제 연결 IP 핀 일치 여부
     (`scope_guard.py`의 `resolved_ips` → `http_client/client.py` 핀 사용).

---

## 5. 하드코딩 시크릿 / 플래그 (1차 스캔)

- 감사 지시문의 "플래그 유출"은 **해당 없음**(플래그 개념 부재).
- `.env.example` 존재(`.env.example`, 1958 bytes) — PHASE 2에서 실제 시크릿
  대 예시값 구분 필요. 현재까지 하드코딩된 실 크리덴셜 미발견(UNVERIFIED,
  전수 grep은 PHASE 2).

---

## 6. UNVERIFIED / 후속 확인 목록 (PHASE 1 시점)

- **UNVERIFIED-SCOPE**: 감사 프레임을 "취약 챌린지 감사"→"방어형 도구 안전성
  감사"로 재정의하는 것에 대한 사용자 승인.
- CTF 무인 실행이 SSRF/스코프 가드를 우회하지 못함(주장, `README.md:142`) —
  코드 확증 필요.
- `api_host=0.0.0.0`가 실제 호스트 노출로 이어지지 않음 — compose/nginx
  프록시 경로 확증 필요.
- 코드 업로드 archive 안전 검사의 실효성(ZIP slip/링크/nested) — 코드 확증.
- 하드코딩 시크릿 부재 — 전수 grep 필요.

---

## 다음 단계 제안

PHASE 2를 아래 축으로 진행 제안(감사 지시문 축을 이 저장소 실체에 맞게 매핑):

- `audit/01_execution_safety.md` — 아웃바운드 실행·스코프·SSRF·DNS핀·CTF
  무인 실행(지시문 축 C 대응, 최우선)
- `audit/02_upload_and_static_analysis.md` — 코드 업로드 안전성·정적 분석기
  정합성(축 F/G + "죽은 탐지 규칙")
- `audit/03_detection_fidelity.md` — 스캐너/분석기가 실제로 탐지하는가
  (축 A의 도구판 재해석)
- `audit/04_ops_secrets.md` — 배포·시크릿·로깅·재현성(축 D잔여/F)
- `audit/99_final.md` — 통합
