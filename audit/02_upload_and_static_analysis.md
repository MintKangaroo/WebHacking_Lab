# PHASE 2 — 축 F/G: 코드 업로드 안전성 + 정적 분석 정합성("죽은 탐지 규칙")

감사 지시문의 축 F(재현성·운영), G(코드 건전성), 그리고 원래 최우선 관심사였던
"죽은 취약점"의 도구판인 **"죽은 탐지 규칙"**(심어둔 탐지가 실제로 발화하는가)을
이 축에서 다룬다.

---

## G-1. [검증됨·정상] 코드 업로드 방어는 THREAT_MODEL 주장을 실제로 강제

`THREAT_MODEL.md:35-38`은 ZIP Slip, archive bomb, symlink/hard link, 실행 콘텐츠,
업로드 코드 실행 방지를 주장한다. `static_analysis/archive.py`를 라인 단위로
추적한 결과 **주장이 실제로 코드에 강제된다:**

| 위협 | 통제 | 근거 |
| --- | --- | --- |
| ZIP Slip / 경로 탈출 | NFC 정규화 후 절대경로·드라이브·`..`·`.`·backslash·null 거부 | `archive.py:39-51` |
| 심볼릭 링크(ZIP) | `S_IFMT(external_attr>>16)==S_IFLNK` 거부, regular/dir 외 거부 | `archive.py:167-172` |
| 실행 파일 | 확장자 blocklist + `mode & 0o111` 거부 | `archive.py:54-58,175` |
| 바이너리/실행 콘텐츠 | ELF(`\x7fELF`)/MZ/null 바이트 헤더 거부 | `archive.py:198-201` |
| Archive bomb | 선언 `file_size` 상한 + 실제 기록 바이트를 선언치로 캡 + 전체·파일수 상한 | `archive.py:181-194` |
| 중첩 아카이브 | 확장자 기반 거부 | `archive.py:27,176-177` |
| 암호화 ZIP | `flag_bits & 0x1` 거부 | `archive.py:165-166` |
| 중복 경로 | 정규화 경로 집합 중복 거부 | `archive.py:117-118,162-163` |
| 코드 실행 | import/build/run 경로 없음; AST/lexer만 | `taint_engine.py`(subprocess 없음) |

세부 검증 노트:
- **`external_attr==0`인 심링크 우회 시도**도 안전하다: mode 0이면 symlink로
  탐지되진 않지만 `zipfile.open`으로 바이트를 **일반 파일로** 기록하므로 디스크에
  실제 심링크가 생기지 않는다(링크 타깃 문자열이 파일 내용이 될 뿐).
- **유니코드 정규화 우회**(예: fullwidth `．．`)는 NFC가 ASCII `.`로 바꾸지
  않으므로 `..` 리터럴 검사를 뚫지 못한다. join 결과도 staging 내부에 머문다.
- `os.replace`로 원자적 배치(`archive.py:98`), `resolve`/`delete`는
  DB 소유 UUID 키만 받고 부모 디렉터리 일치를 강제한다(`archive.py:203-217`).

→ **실제 우회 경로를 발견하지 못했다.** 업로드 경계는 견고하다.

### G-1a. [LOW / 효율] `_reject_binary_header`의 전체 파일 읽기
`archive.py:199`의 `path.read_bytes()[:4096]`는 4KB만 검사하면서 파일 전체를
메모리로 읽는다. 파일당 최대 `max_single_file_bytes`(기본 5MB)이므로 보안
문제는 아니나, 큰 소스에서 불필요한 메모리 I/O가 발생한다. `open(...).read(4096)`
권장. 순수 효율 항목(취약점 아님).

---

## G-2. [검증됨·정상] 정적 탐지 규칙은 "죽지 않았다" — 회귀 테스트로 발화 확인

감사 원칙 3("취약하다고 쓰인 것을 믿지 말고 실제 발화를 코드로 확인")을 이 도구의
탐지 규칙에 적용했다. 정적 taint 엔진(`languages/python/taint_rules.py`,
`languages/php/parser.py`)의 탐지가 **실제로 발화하며 회귀 테스트로 고정**되어
있음을 확인했다.

`backend/tests/test_static_taint_analysis.py`를 실제 실행: **통과.**

```
.venv/bin/pytest tests/test_static_taint_analysis.py tests/test_scope_guard.py -q
33 passed
```

검증된 탐지(양성):
- Flask SQLi: `request.args["id"]`→cursor.execute, source line 3 / sink line 5,
  `SQL_INJECTION`, `STATIC_CANDIDATE` (`test:45-65`)
- Flask SSTI/command/path-traversal 동시 탐지 (`test:76-92`)
- PHP superglobal→`mysqli_query` SQLi, `include($_GET)` LFI (`test:134-152`)
- PHP `$_GET`→raw output XSS (`test:169-179`)

검증된 미탐(음성, 오탐 억제):
- 파라미터라이즈드 쿼리 → finding 없음 (`test:73`)
- 강한 sanitizer → 후보 억제, "strongly sanitized" 사유 기록 (`test:95-102`)
- PHP prepared statement / html escaping → safe (`test:155-165`)

→ 구현된 Python(Flask)·PHP taint 규칙은 **죽은 규칙이 아니다.** 발화·억제 양쪽이
테스트로 보장된다. 결과가 항상 `STATIC_CANDIDATE`에 머무는 것도 설계대로다
(`README.md:157`).

---

## G-3. 커버리지 갭 (탐지 규칙으로서)

정적 taint는 **함수 내부** Python(Flask)과 **보수적 statement** PHP에 한정된다
(`README.md:157,341`). 함수 간 호출, alias, dynamic include는 분석 한계로 표시.
FastAPI/Django/Express/Laravel/Spring 심화 규칙, hybrid 런타임 검증은 미구현
(`README.md:342`). 이는 "죽은 규칙"이 아니라 로드맵상 미구현이며, 도구가 스스로
한계를 명시하므로 과대주장 결함은 아니다.

---

## F-1. 재현성·리셋 (부분 검증)
- 단일 명령 기동 존재: `docker compose up --build`(`README.md:29-34`).
- backend는 `read_only: true` + named volume `webhacking_data`, SQLite는
  `/app/data`에 영속(`docker-compose.yml:10,16`). **리셋 절차/시드 멱등성은
  코드로 미확인** → UNVERIFIED. 취약 랩 자체가 없으므로 "DB 오염 후 복구"의
  대상이 현재는 앱 상태 DB뿐.
- 이미지 버전 고정: Dockerfile pin 여부 미확인 → UNVERIFIED(축 F 잔여).

---

## UNVERIFIED (이 축)
- 액티브 스캐너 **플러그인**(`scanner/plugins`)의 탐지 정합성 — SQL 오류/boolean/
  XSS marker/redirect 판정이 실제 응답에서 올바르게 발화하는지. taint와 달리 아직
  미확인. `test_safe_scanner_plugins.py` 존재하나 미검토.
- Dockerfile 이미지 태그 고정 여부(F).
- 시드/리셋 멱등성(F).

## 다음
남은 고가치 항목: (1) 액티브 스캐너 플러그인 탐지 정합성, (2) redaction/audit
로그의 시크릿 노출(축 D잔여/G) → `audit/03_detection_and_redaction.md`.
그 후 `audit/99_final.md` 통합.
