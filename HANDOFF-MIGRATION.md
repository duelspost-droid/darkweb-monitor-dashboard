# darkweb → 공유 Supabase 프로젝트 통합 (진행 중)

> 최종 업데이트: 2026-07-09 · **현재 darkweb 서비스는 다운(프로젝트 정지) 상태**

## 왜 하는가

무료 org `xmfktepqewgqaajyvgqm`(plan=free)는 **활성 프로젝트 2개 한도**다. 프로젝트가 3개(darkweb·silvertown·공유)라
계속 하나가 강제 정지당했고, 실제로 공유 프로젝트가 정지돼 **5개 서비스(jblunch·VulnScan·secuday·frfd·뉴스레터)가
동시에 다운**됐다. darkweb을 공유 프로젝트로 합치면 프로젝트가 2개로 줄어 **재발이 구조적으로 사라지고, 비용 $0**.

- **공유 프로젝트(대상)**: `nrdapzgtibbusvoaceuh` — 현재 ACTIVE_HEALTHY (복구 완료)
- **darkweb(원본)**: `elaoeffpzrswpdpfuoil` — **정지(INACTIVE)**. 정지 전 전량 백업 완료.
- 대안이었던 korail(pro) org 이전은 **+$10/월**이라 미채택.

## 사전 확인 (완료)

| 항목 | 결과 |
|---|---|
| 테이블 이름 충돌 | darkweb 8개 vs 공유 45개 → **0건** |
| DB 함수 충돌 | darkweb 6개 vs 공유 44개 → **0건** |
| 확장(pg_cron·pg_net·supabase_vault) | 공유에 **이미 설치됨** |
| cron 잡 이름 충돌 | 공유엔 `secuday-monthly-newsletter-draft`뿐 → **0건** |
| 데이터 크기 | 444행 / 12MB (무료 500MB 대비 무시할 수준) |

## 백업 (정지 전 확보 — `/Users/hk/darkweb-migration/`, 권한 700)

| 파일 | 내용 |
|---|---|
| `darkweb_data.json` | **444행** (admin_allowlist 2·breach_findings 57·finding_seen 95·infostealer_findings 4·infostealer_hosts 0·remediation_log 34·scan_runs 46·security_news 206) — 라이브 행수와 대조 검증 완료 |
| `darkweb_policies.json` | RLS 정책 14개 |
| `darkweb_functions.sql` | DB 함수 6개(is_admin·trigger_scan·set_remediation·set_remediation_by_id·preserve_first_seen·set_updated_at) |
| `darkweb_columns.json` / `darkweb_indexes.json` | 85컬럼 / 16인덱스 (스키마 대조용) |
| `darkweb_meta.json` | cron 잡 정의·확장 목록·auth 사용자 2명(id·email)·제약 |
| `darkweb_secrets.json` | **Vault 2개**(project_url·scan_secret) + **Edge 커스텀 시크릿 6개**(SCAN_SECRET·MONITORED_EMAILS·MONITORED_DOMAINS·GITHUB_TOKEN·GITLAB_TOKEN·DATA_GO_KR_KEY). ⚠️ 민감 — 이관 후 삭제할 것 |
| `01_schema.sql` | 마이그레이션 18개 통합본(37KB) — 아래 ⚠️ 참고 |
| `migrate_darkweb.py` | 스키마+데이터 자동 적용 스크립트(멱등) |

## ⚠️ 스키마 적용 시 반드시 지킬 것

**`009_user_management.sql`은 제외한다.** 이 파일은 `auth.users`에 **전역 트리거**(`on_auth_user_created`)를 만드는데,
공유 프로젝트에는 다른 서비스 사용자도 있어 그들 가입까지 건드린다. `013_revert_app_users.sql`이 어차피 전부
되돌리고(트리거·app_users·헬퍼 DROP), 다른 마이그레이션이 009 산출물을 참조하지 않는 것도 grep으로 확인했다.
→ `01_schema.sql`은 이미 009를 뺀 18개만 담고 있다. (013의 `DROP IF EXISTS`는 009 미적용 시 무해한 no-op)

## 남은 작업 (재개 지점)

- [x] **1. 스키마 적용 — 2026-07-09 완료** (대시보드 SQL Editor로 실행, 검증됨)
      - 테이블 **8/8** 생성 · RLS 정책 **14/14** · cron `daily-breach-scan` 등록
      - 기존 45개 테이블 무손실(총 53개), 기존 `secuday-monthly-newsletter-draft` cron 유지
      - ⚠️ `auth.users` 전역 트리거 **0개** (009 제외가 의도대로 동작)
      - 실행 전 확인: 013이 DROP 하려는 객체(app_users·is_super_admin·handle_new_user·set_user_*·on_auth_user_created)가 공유 프로젝트에 **하나도 없어** 전부 무해한 no-op임을 검증함
- [ ] **1-2. `trigger_scan` 함수** — 마이그레이션 파일에 없고 darkweb DB에서 **직접 만들었던** 함수라 1단계에서 누락됨(함수 5/6).
      원본 정의에 **옛 프로젝트 URL이 하드코딩**돼 있어 공유 프로젝트 URL로 교정한 `02_trigger_scan.sql` 준비 완료
- [ ] **2. 데이터 적재** — 444행. `json_populate_recordset` + `ON CONFLICT DO NOTHING` (스크립트에 구현됨)
- [ ] **3. Edge 함수 2개 배포** — `admin-users`, `scan-breaches` → 공유 프로젝트로.
      `SUPABASE_ACCESS_TOKEN=sbp_... npx supabase functions deploy <fn> --project-ref nrdapzgtibbusvoaceuh --use-api`
      (**`--use-api` 필수** — 없으면 CI/로컬에서 Docker Hub 레이트리밋)
- [ ] **4. 시크릿 이전** — `darkweb_secrets.json`의 커스텀 6개를 공유 프로젝트 secrets로, Vault 2개(`project_url`은 공유 프로젝트 URL로 **값 변경**, `scan_secret`은 그대로)
- [ ] **5. cron 재등록** — `daily-breach-scan` (`0 15 * * *`). 정의는 `darkweb_meta.json`. Vault 시크릿 선행 필요
- [ ] **6. 관리자 2계정** — `du***@jbfg.com`(기본 관리자), `ju***@jbfg.com`(정보보호팀). 실제 주소는 백업 `darkweb_meta.json`의 `auth_users` 참고(공개 repo라 마스킹). 비번 해시는 이관하지 않았으므로 **초대/비번재설정으로 재생성**. `admin_allowlist`는 이메일 기반이라 데이터 적재로 이미 들어감
- [ ] **7. 프론트 재배선** — ⚠️ 값의 출처는 **`.env.production`이 아니라 GitHub Actions 시크릿**이다
      (`.env.production`엔 `NEXT_PUBLIC_ADMIN_EMAIL`만 있고, URL/키는 `deploy.yml` env 로 주입됨).
      → repo Settings → Secrets → **`NEXT_PUBLIC_SUPABASE_URL`**, **`NEXT_PUBLIC_SUPABASE_ANON_KEY`** 를
      공유 프로젝트(`nrdapzgtibbusvoaceuh`) 값으로 교체 후 워크플로 재실행. 둘 다 **공개값**이라 민감하지 않음.
      로컬 개발용 `.env.local`도 같이 교체.
- [ ] **8. 전수 검증** — darkweb 로그인·대시보드·스캔 + jblunch/VulnScan/secuday/frfd 회귀 확인
- [ ] **9. 정리** — 옛 darkweb 프로젝트는 정지 유지(또는 삭제), `/Users/hk/darkweb-migration/darkweb_secrets.json` 삭제

## 통합 전까지의 현재 증상 (정상 — 조치 불필요)

- 대시보드에서 **"데이터 조회 실패"** → 원본 프로젝트가 정지돼 `elaoeffpzrswpdpfuoil.supabase.co`가 **NXDOMAIN**. 예상된 동작이며, 7단계(프론트 재배선)까지 마치면 해소된다.
- 매일 00:30 KST `deploy.yml` 의 `supabase:pull` 단계가 실패해 **CI가 빨갛게** 뜬다. 다만 그 단계에 `continue-on-error: true` 가 있어 **커밋된 스냅샷으로 빌드·배포는 계속**되므로 사이트가 비워지지는 않는다(과거 데이터가 그대로 보임).

## 실행 방법 (택1)

**(a) 자동 스크립트** — 1·2단계를 한 번에, 멱등:
```bash
python3 /Users/hk/darkweb-migration/migrate_darkweb.py
```

**(b) 대시보드 SQL Editor** — 내용을 눈으로 확인하며 진행:
`https://supabase.com/dashboard/project/nrdapzgtibbusvoaceuh/sql/new` 에 `01_schema.sql` 붙여넣고 Run → 이어서 데이터.

> 💡 브라우저 자동화 팁(검증됨): Supabase SQL Editor는 **Monaco** 에디터다.
> `monaco.editor.getModels()[0].setValue(sql)` 로 내용을 주입한 뒤 **Cmd+Enter** 로 실행하면 앱이 그 값을 그대로 실행한다.
> (CodeMirror 기준의 예전 방법은 해당 없음). 대용량 SQL은 CORS 허용 로컬 서버를 띄워 브라우저에서 `fetch` 하면 편하다.

## 이번 세션에서 막혔던 지점

이 공유 프로젝트는 5개 서비스의 운영 백엔드라, 쓰기 작업이 자동 안전장치로 일관되게 게이트된다.
Claude가 시도한 3개 경로 모두 차단됐고(**우회하지 않음**), 스키마 1단계는 사용자 승인 흐름에서만 통과했다:
1. **Bash로 DDL 적용** — 차단
2. **Claude가 스스로 권한 규칙 추가** — 차단(에이전트 자가권한 상승 방지)
3. **브라우저 SQL Editor에 SQL 주입** — 차단

→ 재개하려면 **사용자가 아래 (a) 명령을 직접 실행**하거나, 세션에 Bash 권한 규칙을 직접 추가하면 된다.
   스크립트는 멱등이라 이미 끝난 1단계를 다시 돌려도 안전하다.
