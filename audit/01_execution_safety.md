# PHASE 2 — 축 C: 아웃바운드 실행 안전성 (SSRF / 스코프 / DNS핀 / CTF 무인 실행)

감사 지시문 축 C(격리·안전성)를 이 도구의 실체에 맞게 적용한다. 대상은
"의도적으로 취약한 표적이 랩 밖으로 새는가"가 아니라 **"이 도구의 아웃바운드
공격 능력이 문서화된 안전 경계를 실제로 지키는가"**다.

---

## C-1. [MEDIUM] README가 사설(RFC1918)·loopback IP 차단을 보장한다고 과대주장 — 실제로는 차단하지 않음. CTF 무인 모드에서 실질 위험

### 주장
README는 스코프 가드가 사설 IP를 차단하며, 이 보호가 CTF 모드에서도 유지된다고
명시한다:

- `README.md:142`: "완화되는 것은 **인가·승인 절차뿐**입니다. Scope Guard의
  **SSRF·사설·메타데이터 IP 차단**, 민감정보 마스킹, ... 은 그대로 적용됩니다."
- `README.md:163`: "SSRF 방지 URL/DNS/IP/metadata/link-local 정책"

### 코드 사실
스코프 가드의 IP 차단 함수 `_blocked_ip_reason`
(`backend/webhacking_lab/http_client/scope_guard.py:89-102`)이 차단하는 것은
**metadata / unspecified / multicast / link-local / reserved 뿐이다.**
`is_private`(RFC1918)와 IPv4 `is_loopback`에 대한 검사가 없다.

실측(파이썬 `ipaddress`):

| 주소 | 차단됨? | 근거 |
| --- | --- | --- |
| `127.0.0.1` (IPv4 loopback) | ❌ **통과** | loopback만 True, reserved/link-local False |
| `10.0.0.5`, `192.168.1.1`, `172.16.0.1` | ❌ **통과** | private만 True |
| `fd00::1` (IPv6 ULA) | ❌ **통과** | private만 True |
| `::1` (IPv6 loopback) | ✅ 차단 | 우연히 `is_reserved=True` |
| `169.254.169.254` | ✅ 차단 | link-local + metadata |
| `100.100.100.200` (Alibaba metadata) | ✅ 차단 | METADATA_ADDRESSES |

즉 **README가 차단된다고 명시한 "사설 IP"는 차단되지 않는다.** IPv4 loopback도
차단되지 않는다(IPv6 loopback만 우연히 reserved로 잡힘 — 일관성 없음).

### CTF 무인 실행에서의 실질 영향
스코프 가드는 본질적으로 **allowlist 게이트**이지 내부대역 denylist가 아니다.
일반(SAFE) 모드에서는 내부 IP에 도달하려면 사용자가 직접 스코프 규칙을
등록하고 `authorization_confirmed`를 확인해야 하므로 사람이 명시적으로 표적을
지정하는 셈이라 문제가 아니다.

그러나 **CTF 프로필은 이 사람 확인 단계를 자동화한다**
(`backend/webhacking_lab/services/scans.py:202-219`):

- 붙여넣은 대상 host가 `not_in_scope`면 `_register_ctf_scope`로
  **자동 등록**하고(`scans.py:210`), 이어서 `authorization_confirmed=True`로
  **자동 승인**(`scans.py:216-217`)한다.
- 이후 read-only 액티브 프로브(SQL 오류/UNION/boolean, XSS marker,
  `/etc/passwd` traversal, open redirect)가 **무인 실행**된다
  (`scanner/active_engine.py`, `execution_policy.py:22-32`).

결과: CTF 모드에서 운영자가 `http://192.168.0.10/admin?id=1` 같은 **내부
주소를 붙여넣으면, 추가 확인 없이 자동 등록·승인되어 내부 호스트에 실제 탐지
페이로드가 발사된다.** README는 "사설 IP 차단이 그대로 적용된다"고 안심시키지만
그 보호는 존재하지 않는다.

메타데이터는 여전히 안전하다: 대상이 메타데이터/link-local로 해석되면
`decision.code`가 `ip_policy_blocked`가 되어 `not_in_scope` 자동등록 분기를
타지 않고 `scans.py:213`에서 차단된다. **차단 우회는 사설/loopback 대역에
한정된다.**

### THREAT_MODEL과의 관계 (중요)
`docs/THREAT_MODEL.md:26,28,29`는 SSRF 통제를 **"scope allowlist + DNS/IP policy
+ metadata deny"**로만 기술하고 **사설 대역 차단을 주장하지 않는다.** 즉
코드는 위협모델과 일치하며, **불일치는 README의 과대주장에 있다.** 따라서 이
항목의 핵심 결함은 "통제 우회"가 아니라 **안전 보장에 대한 문서-구현 불일치**이며,
CTF 무인 모드가 사람 확인을 제거하기 때문에 그 오해가 실제 피해로 이어질 수 있다.

### 권고
- README `:142`, `:163`에서 "사설 IP 차단" 문구를 제거하거나, 실제로
  `_blocked_ip_reason`에 `is_private`·IPv4 `is_loopback` 차단을 추가하되
  **로컬 랩/loopback 사용은 `WorkspaceMode.LOCAL_LAB`로 명시적으로만 허용**하도록
  분기. 최소한 CTF 자동등록 분기(`scans.py:202-212`)에서 사설/loopback 대상은
  자동승인하지 말고 명시적 확인을 요구.
- IPv4/IPv6 loopback 처리의 비일관성(`::1`만 차단됨)을 통일.

### 상태: **CONFIRMED → RESOLVED(문서)** (코드+실측)
[2026-08-14] 사용자 결정으로 **문서 정정**을 통해 해소. `README.md:142,165`에서
"사설 IP 차단" 거짓 보장을 제거하고 allowlist 모델과 사설/loopback 비차단(의도),
CTF 무인 프로빙 경고를 명시. 코드는 의도적으로 유지(공개·사설 CTF paste-and-go
요구사항). C-1은 이제 문서-구현 정합.

---

## C-2. [검증됨·정상] DNS 리바인딩 핀은 실제로 작동

위협모델 `THREAT_MODEL.md:28`의 "validate all answers and pin the approved
address per attempt"는 코드로 실제 강제된다:

- `ScopeGuard.check`가 DNS 응답 전체를 resolve하고 각 IP를 `_blocked_ip_reason`로
  검사한 뒤 `decision.resolved_ips`에 담는다(`scope_guard.py:167-199`).
- 실행 시 `send(resolved_ips=decision.resolved_ips,
  expected_hostname=decision.hostname)`로 전달되고
  (`services/request_execution.py:389-396`),
- `PinnedNetworkBackend.connect_tcp`는 host가 expected_hostname과 일치할 때만,
  그리고 **검증된 IP 목록으로만** 연결한다
  (`http_client/client.py:64-78`). 연결 시점 재해석이 없다.

→ 검증-후-연결 사이 재resolve가 없어 리바인딩이 무력화된다. **정상 작동.**
단 C-1과 결합: 핀되는 IP 자체가 사설/loopback이면 검증을 통과한다.

---

## C-3. [검증됨·정상] 리다이렉트 스코프 탈출 방지

`services/request_execution.py:376-421` 실행 루프는 매 홉마다
`_scope_decision`을 재실행하고(`:377`, `:407`), 스코프를 벗어나면
`ExecutionPolicyError`가 발생해 차단·감사된다(`:214-215`, `:422-424`).
HTTPS→HTTP 다운그레이드 리다이렉트도 차단된다(`:408-409`). 액티브 스캐너
프로브는 `follow_redirects=False`로 실행되어 애초에 리다이렉트를 따르지 않는다
(`active_engine.py:215,231`). **정상 작동.**

---

## C-4. [검증됨·정상] 저장 자격증명 미재전송 / 안전 메서드 한정

`_outbound_request`(`request_execution.py:91-118`)는 GET/HEAD/OPTIONS만 허용하고
body를 제거하며, redacted query와 비허용 헤더(쿠키·Authorization 등)를 제거한다.
`confirmation_phrase`는 pydantic `Literal["SEND UP TO 5 SAFE REQUESTS"]`로
스키마에서 강제된다(`api/schemas/resources.py:255`) — UI 장식이 아니라 실제
타입 강제. **정상 작동.**

---

## C-5. [검증됨·정상] 서버 전역 게이트

`RequestExecutionService._check_server_policy`(`request_execution.py:174-176`)와
`ScanService.create`(`scans.py:161-166`)는 `analysis_only=True`이거나
`network_execution_enabled=False`이면 모든 실행을 거부한다. CTF 프로필은
`ctf_mode_enabled=True`까지 추가로 요구한다(`scans.py:163-166`). 기본값은 세
스위치 모두 안전측(`core/config.py:30-32`). **정상 작동** — 다만 이 게이트가
풀린 뒤의 CTF 무인 경로가 C-1의 대상이다.

---

## UNVERIFIED (이 축)
- 레이트리밋/동시성/예산이 다중 동시 스캔에서 실제로 프로세스 전역 상한을
  지키는지(`core/rate_limit.py`) — 코드 미확인. README `:345`는 단일 인스턴스
  한정임을 인정. 별도 심층 필요.
- `_gate.slot`의 target_key가 스킴+netloc 기준이라 동일 IP·다른 호스트명에서
  레이트 우회 가능성 — 미확인.

## 다음
`audit/02_upload_and_static_analysis.md`에서 코드 업로드(ZIP slip/링크/자원)와
정적 분석기 정합성(축 F/G + 죽은 탐지 규칙)을 감사한다.
