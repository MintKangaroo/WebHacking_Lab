# PHASE 3 — 통합 리포트

## 감사 대상과 범위 정정 (반드시 먼저 읽을 것)

감사 지시문은 **의도적 취약 CTF 챌린지 세트**를 전제했으나, 실제 저장소는
**통제형(방어지향) 웹 보안 분석 도구 플랫폼**이다. 취약 챌린지·플래그·채점
로직이 존재하지 않으며, 취약 랩(`labs/`)은 Phase 6 미구현이다
(`labs/README.md`, `README.md:338-343`). 근거·상세는 `audit/00_inventory.md` §0.

따라서 감사를 **"이 도구의 아웃바운드 공격 능력이 문서화된 안전 경계를
지키는가"**로 재정의해 수행했다(사용자 승인 완료). 지시문 축과의 매핑:

| 지시문 축 | 이 저장소에서의 적용 | 결과 파일 |
| --- | --- | --- |
| A 익스플로잇 가능성 | 해당 없음(취약 표적 부재) → 도구의 **탐지 규칙 발화**로 재해석 | 02 §G-2, 03 §2 |
| B 의도치 않은 해법 | 해당 없음(챌린지 부재) | — |
| C 격리·안전성 | **최우선**: SSRF/스코프/DNS핀/CTF 무인 실행 | 01 |
| D 플래그·채점 | 해당 없음 → redaction/로그로 재해석 | 03 §3 |
| E 난이도·학습가치 | 해당 없음(챌린지 부재) | — |
| F 재현성·운영 | 이미지 고정/리셋/기동 | 03 §4 |
| G 코드 건전성 | 업로드 안전성/게이트 단일화/탐지 정합성 | 02, 03 |

---

## 1. 죽은 취약점 / 뚫리지 않는 챌린지

**해당 없음** — 의도적 취약 챌린지가 존재하지 않는다.

도구판 재해석("죽은 탐지 규칙")으로 확인한 결과, 구현된 탐지는 **죽지 않았다**:
- Python(Flask)/PHP 정적 taint 발화 + sanitizer 억제가 회귀 테스트로 고정,
  실제 실행 통과(`audit/02_upload_and_static_analysis.md` §G-2, `33 passed`).
- 스캐너 플러그인 판정(오류→CONFIRMED, boolean→LIKELY, 무신호→FALSE_POSITIVE)이
  보정되어 있고 테스트 통과(`audit/03` §2, `15 passed`).

---

## 2. 의도치 않은 해법 목록

챌린지가 없으므로 "우회 해법"은 해당 없음. 대신 **안전 경계 우회/과대주장**을
아래 §3에 정리한다.

---

## 3. 안전성 결함 (랩 밖으로 새는/오해를 부르는 경로)

### 3-1. [MEDIUM · CONFIRMED] README가 "사설 IP 차단"을 보장하나 실제로는 미차단 — CTF 무인 모드에서 실질 위험
- 근거: `http_client/scope_guard.py:89-102`는 metadata/unspecified/multicast/
  link-local/reserved만 차단. **RFC1918 사설·IPv4 loopback은 통과**(실측 및
  `test_scope_guard.py:93,112`가 오히려 allowlist 설계임을 확증).
- CTF 프로필은 붙여넣은 대상을 **자동 등록·자동 승인·무인 실행**하므로
  (`services/scans.py:202-217`), 내부 주소를 붙여넣으면 확인 없이 능동 프로브가
  내부 호스트로 발사된다.
- 핵심: `THREAT_MODEL.md`는 사설 차단을 주장하지 않아 코드와 일치하며,
  **불일치는 `README.md:142,163`의 과대주장에 있다.** (메타데이터는 여전히 차단.)
- 상세·권고: `audit/01_execution_safety.md` C-1.
- **[조치 완료 2026-08-14]** 사용자 결정에 따라 **문서 정정**으로 해소.
  `README.md:142`(CTF 프로필 주의문)과 `README.md:165`(기능 목록)에서 "사설 IP
  차단" 거짓 보장을 제거하고, Scope Guard가 allowlist 모델이며 사설/loopback은
  차단되지 않음(로컬 랩·HTB류 VPN 대상 `10.10.x.x` 지원을 위한 의도된 동작)을
  명시. **코드는 의도적으로 변경하지 않음** — 공개·사설 대상 모두 CTF
  paste-and-go 유지가 사용자 요구사항이므로. 잔여 위험(내부 주소 붙여넣기 시
  무인 프로빙)은 이제 문서에 정직하게 경고됨.

### 3-2. [LOW · 조치 완료 2026-08-15] 비구조화 텍스트/비민감 JSON 키의 시크릿 마스킹
- 기존: `redact_text`의 키워드가 좁고(`redaction.py`), `redact_mapping`은 키
  기준이라 평문 body/비민감 키의 토큰이 `[REDACTED]` 없이 저장 가능했다.
- **조치**: 키 이름 비의존 **값-형태 탐지**(JWT·`Bearer`/`Basic`·고엔트로피
  토큰)를 `redact_value_shapes()`로 추가하고 `redact_text`/`redact_mapping`
  문자열 리프/`redact_pairs` 비민감 값 경로에 적용. 저엔트로피 산문은 보존.
  회귀 테스트 추가, 전체 스위트 133 passed.
- 상세: `audit/03` §3-2.

### 3-3. [LOW] Rate 게이트 target_key 분할 / 3-4. [LOW] Docker digest 미고정 / 3-5. [LOW] IPv4·IPv6 loopback 처리 비일관
- 각각 `audit/03` §1a, §4, `audit/01` C-1 참조. 모두 저위험.

### 검증되어 정상 작동하는 통제 (결함 아님, 기록)
DNS 리바인딩 핀, 리다이렉트 매 홉 재검사, HTTPS→HTTP 다운그레이드 차단, 자격증명
미재전송, GET/HEAD/OPTIONS 한정, `confirmation_phrase` 타입 강제, **단일 게이트
강제(크롤러/액티브/수동 공통)**, 예산·페이싱, 코드 업로드 방어(ZIP slip/심링크/
실행/폭탄/중첩/암호화 — 우회 미발견), 컨테이너 하드닝(read_only/cap_drop/
no-new-privileges), 메타데이터 차단. 근거: `audit/01` C-2~C-5, `audit/02` G-1,
`audit/03` §1.

---

## 4. 커버리지 갭 (OWASP / 웹 CTF 기준)

**실습 표적 관점**: 16개 축 전부 공백(취약 챌린지 미구현, Phase 6 예정). 이는
설계상 미도달 단계이지 결함이 아니다. 상세 매트릭스: `audit/00_inventory.md` §3.

**도구 탐지 규칙 관점**: SQLi/XSS(reflected)/traversal/open-redirect/CORS/JWT/
security-header/정적 taint(Flask·PHP)는 구현. **미구현**: NoSQLi, SSTI 능동탐지,
역직렬화, XXE, GraphQL, CSRF 능동탐지, IDOR, 레이스컨디션, stored/DOM XSS,
함수간 taint, FastAPI/Django/Express/Laravel/Spring 심화. 도구가 스스로 한계를
명시하므로(`README.md:157,340-342`) 과대주장 결함은 아님.

---

## 5. 우선순위 매트릭스 (학습/안전 영향 × 수정 비용)

```
              수정 비용 낮음                    수정 비용 높음
          ┌────────────────────────────┬────────────────────────────┐
   영향   │ 3-1 README 사설IP 과대주장   │ (해당 없음)                  │
   높음   │  → 문구 수정 or CTF 자동승인 │  구조적 재작업 필요 항목 없음 │
          │    에서 사설/loopback 제외   │                             │
          ├────────────────────────────┼────────────────────────────┤
   영향   │ 3-2 redaction 문구 정정      │ 3-2 값-형태(JWT/entropy)     │
   낮음   │ 3-4 Docker digest 고정       │     시크릿 탐지 추가          │
          │ 3-5 loopback 처리 통일       │ 1a  분산 rate(공유 저장소)   │
          └────────────────────────────┴────────────────────────────┘
```

**즉시 조치 권고(저비용·고영향)**: 3-1. 두 가지 중 택1 —
(a) `README.md:142,163`에서 "사설 IP 차단" 문구 삭제·정정, 또는
(b) `scope_guard._blocked_ip_reason`에 `is_private`·IPv4 `is_loopback` 차단을
추가하고 로컬 사용은 `WorkspaceMode.LOCAL_LAB`로만 명시 허용 + CTF 자동승인
분기(`scans.py:202-217`)에서 사설/loopback 대상은 명시 확인 요구.

---

## 6. UNVERIFIED 목록

1. 다중 워커(gunicorn -w N) 배포 시 프로세스 전역 rate 상한 분리 — 실제 배포
   워커 수 미확인(README `:345` 한계 인정).
2. Redaction 값-형태 시크릿 미탐의 end-to-end 저장 영향.
3. 리셋/시드 멱등성 — 취약 랩 미구현이라 현재 대상은 앱 상태 DB뿐.
4. `api_host=0.0.0.0`(`config.py:23`)의 실제 호스트 노출 여부 — compose상 backend
   포트 미매핑이라 현재 미노출로 보이나 nginx 프록시 라우팅 전수 미확인.
5. 하드코딩 실 크리덴셜 부재 — 전수 grep 미완(`.env.example`만 확인).
6. 감사 프레임 재정의(취약 챌린지→방어형 도구)는 사용자 승인 완료(UNVERIFIED-
   SCOPE 해소).

---

## 종합

이 저장소는 감사 지시문이 전제한 "취약 CTF 랩"이 아니라 **안전 경계를 스스로
강제하는 방어형 분석 도구**다. 실행·업로드·탐지의 핵심 통제는 코드와 회귀
테스트로 실제 작동함을 확인했고, 실행 가능한 아웃바운드 경로는 단일 스코프
가드/게이트로 수렴한다. **유일한 유의미 결함은 문서-구현 불일치(3-1)**로,
README가 존재하지 않는 사설 IP 차단을 보장하며 그 오해가 CTF 무인 모드에서
내부망 프로빙으로 이어질 수 있다. 나머지는 저위험 정밀도·재현성 항목이다.
```
검증에 사용한 실행 증거: pytest 48 passed
(taint 33 + plugins/redaction 15), 실 외부 요청 없이 fake DNS/loopback.
```
