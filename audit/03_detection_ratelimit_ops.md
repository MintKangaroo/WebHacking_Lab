# PHASE 2 — 축 D/F/G 잔여: 탐지 정합성 · Rate/Gate · Redaction · 운영

---

## 1. [검증됨·정상] 단일 게이트 강제 — 크롤러/액티브/수동 모두 동일 경로

`THREAT_MODEL.md:43` "one guarded client injected into all execution-capable
services"를 코드로 확인:

- Passive 크롤러 fetch는 `RequestExecutionService.execute`를 경유
  (`scanner/engine.py:411`).
- `execute` 내부에서 실제 send가 `self._gate.slot(...)` + `consume_request_budget`
  로 감싸진다(`services/request_execution.py:380-388`).
- 액티브 테스트도 동일 서비스 사용(`scanner/active_engine.py:203-232`), 수동
  리피터도 동일.

→ **rate limit / scope guard / 예산을 우회하는 아웃바운드 경로 없음.** 크롤러는
추가로 `requests_per_second` 페이싱까지 적용(`engine.py:178-184`). Logout 유사
경로는 요청하지 않고 기록만 한다(`engine.py:383-388`).

### 1a. [LOW · 조치 완료 2026-08-15] Rate 게이트의 target_key 분할 가능성
기존: `_gate.slot`의 `target_key`가 `scheme://netloc`(원문 그대로)이라, 동일
호스트를 `example.com`과 `example.com:80`처럼 다른 표기로 접근하면 별도 target
버킷이 되어 **target별** rate가 갈릴 수 있었다. (전역 상한 `global_per_minute`은
항상 적용되므로 총 트래픽은 이미 bounded, `RateLimitError` fail-fast로 은닉
트래픽 없음 — 그래서 LOW.)

- **[조치]** `request_execution._rate_bucket_key(url, hostname)` 헬퍼를 추가해
  버킷 키를 **정규화**: Scope Guard가 소문자화한 `decision.hostname`과 스킴
  기본 포트(http=80, https=443)를 접어 `scheme://host:port` 형태로 생성. 이제
  `example.com` ≡ `example.com:80`(http), 대소문자 변형이 하나의 버킷으로 수렴.
  실제 다른 포트(`:8080`)는 여전히 별개 버킷. 모든 아웃바운드 경로(수동/크롤러/
  액티브)가 `RequestExecutionService`를 통과하므로 단일 지점 수정으로 일괄 적용.
  회귀 테스트 추가(`tests/test_request_execution.py`).
- **범위 밖(미조치, 문서 유지)**: 다중 워커(gunicorn -w N) 간 **프로세스 전역**
  rate 공유는 여전히 미지원 — 공유 저장소(Redis 등) 필요. README `:345`가 단일
  인스턴스 한정임을 이미 명시하므로 과대주장 아님. 완전 분산 rate가 필요하면
  별도 인프라 도입이 전제.

---

## 2. [검증됨·정상] 스캐너 플러그인 판정은 죽지 않았고 과대주장도 안 함

`backend/tests/test_safe_scanner_plugins.py` 실행: **통과(15 passed).**

- SQL 플러그인: 오류 시그널→`CONFIRMED`, boolean 차이→`LIKELY`, 무신호→
  `FALSE_POSITIVE`로 정확히 구분(`test:154-179`).
- reflection/redirect/CORS 플러그인: 신호를 과장하지 않음(대부분 `LIKELY`,
  무신호는 `FALSE_POSITIVE`)(`test:183-226`).
- Security header 어댑터: **요청을 절대 생성하지 않음**→`NOT_TESTED`
  (`test:230-234`).
- 플래너: 정확히 6개 프리뷰 생성, 시크릿 파라미터는 건너뜀(`test:123`).

→ 판정 등급이 증거 강도에 맞게 보정되어 있고 회귀 테스트로 고정. 탐지가
"의도보다 쉽게/과하게" 확정되는 지점 없음.

---

## 3. Redaction / 로그 시크릿 노출 (축 D/G)

### 3-1. [검증됨·정상] 구조화 데이터·헤더·쿠키 마스킹
`core/redaction.py` + `test_redaction_and_normalization.py` 실행: **통과.**
- 헤더/쿠키/폼/JSON은 sensitive 키·suffix(`-token`/`-secret`/`-key`)로 마스킹
  (`redaction.py:41-90`). 쿠키는 이름·속성 보존, 값만 제거(`:48-69`).
- 감사 로그 `details`는 method/hostname/status_code/reason 등 **allowlist 필드만**
  저장(`request_execution.py`, `scans.py`의 `_audit.record` 호출부). 요청 body나
  raw 토큰을 details에 넣는 지점 없음. 앱 미들웨어 로그도 method/path/status만
  기록(`api/app.py:102-108`). → THREAT_MODEL `:34` "allowlist logging" 유지.

### 3-2. [LOW] 비구조화 텍스트/값-형태 시크릿은 best-effort
- `redact_text`의 `ASSIGNMENT_PATTERN`은 `password|passwd|api_key|access_token|
  refresh_token|secret`만 잡는다(`redaction.py:35-38`). **평문 body 안의 bare
  `Authorization`, `token`, `Bearer eyJ...`, JWT 형태 문자열은 마스킹되지 않는다.**
- `redact_mapping`은 JSON을 **키 이름 기준**으로만 마스킹(`:93-105`) — 비민감
  키(`"data"`)에 담긴 토큰 값은 통과.

영향: 외부 실행은 body를 아예 전송하지 않고(`request_execution.py:96-97`), import된
자격증명 헤더는 구조화 마스킹으로 처리되므로 실 위험은 낮다. 다만 사용자가 평문
body/비민감 JSON 키에 시크릿을 붙여넣어 저장하면 `[REDACTED]` 없이 DB에 남을 수
있었다.

- **[조치 완료 2026-08-15]** 키 이름에 의존하지 않는 **값-형태 탐지**를 추가해
  해소. `redaction.py`에 (a) JWT 패턴(`eyJ...` 3분절), (b) `Bearer`/`Basic`
  자격증명, (c) 고엔트로피 토큰(길이 ≥32, 숫자+문자 혼합, Shannon ≥3.5) 탐지를
  넣고 `redact_value_shapes()`로 묶었다. 이를 `redact_text`(평문 body),
  `redact_mapping`의 **문자열 리프**(비민감 JSON 키 값), `redact_pairs`의 비민감
  쿼리/헤더 값 경로 전부에 적용. 저엔트로피 산문·짧은 값·숫자 없는 소문자 런은
  분석 가치를 위해 보존된다(회귀 테스트 3건 추가,
  `tests/test_redaction_and_normalization.py`). 잔여 트레이드오프: 40자 hex
  git SHA 등 고엔트로피 식별자는 보수적으로 마스킹될 수 있음(세션 토큰 오인
  방지를 우선한 의도된 동작).

---

## 4. 운영·재현성 (축 F)

- **이미지 태그 고정**: `python:3.12-slim`, `node:20-alpine`,
  `nginxinc/nginx-unprivileged:1.29-alpine`(`backend/Dockerfile:1,15,32`,
  `frontend/Dockerfile:1,9`). **`latest` 미사용**(랩이 갑자기 안 뜨거나 취약점이
  사라지는 위험 없음). 단 **digest 미고정**이라 minor 패치 드리프트는 가능 —
  재현성 관점 LOW.
- **[결정 2026-08-15] digest 미고정은 의도된 선택으로 확정.** 이 저장소는 방어형
  보안 분석 도구이므로 베이스 이미지가 **최신 보안 패치**를 계속 받는 편이
  digest를 얼려 재현성을 극대화하는 것보다 이득이 크다. `@sha256:` 고정은
  패치 드리프트를 막는 대신 베이스 이미지 취약점을 그대로 동결하므로 채택하지
  않는다. minor 태그(예: `3.12-slim`) 고정으로 "갑자기 안 뜸/취약점 소실" 위험은
  이미 차단되어 있어 잔여 재현성 리스크는 LOW로 수용한다. 완전한 비트 단위
  재현이 필요한 배포에서는 배포 파이프라인에서 digest를 주입하는 것을 권장.
- **단일 명령 기동**: `docker compose up --build`(`README.md:33`).
- **리셋/시드 멱등성**: 시드 데이터·취약 챌린지가 없으므로 "사용자가 DB를
  망가뜨려 복구 불가" 시나리오의 대상은 앱 상태 DB(named volume `webhacking_data`)
  뿐. `docker compose down -v`로 초기화. 취약 랩 리셋 요구사항은 랩 구현(Phase 6)
  전까지 해당 없음.
- **컨테이너 하드닝**: `read_only`, `cap_drop: ALL`, `no-new-privileges`
  (`docker-compose.yml:19-25,49-61`) — THREAT_MODEL `:41` "Lab breakout" 통제와
  일치.

---

## UNVERIFIED (이 축)
- `_gate`가 **프로세스 전역 단일 인스턴스** 상태라 다중 워커(gunicorn -w N)
  배포 시 전역 상한이 워커별로 분리됨 — README `:345`가 인정한 한계. 실제 배포
  Dockerfile의 워커 수 미확인.
- Redaction의 값-형태(entropy/JWT) 탐지 부재가 실제 저장 데이터에서 문제가 되는지
  end-to-end 미검증.
