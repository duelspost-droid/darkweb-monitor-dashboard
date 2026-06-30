# 다크웹 유출 모니터링 대시보드 — 개발 핸드오프 (HANDOFF)

**최종 갱신: 2026-06-25**

> ⚠️ **공개 repo 커밋됨 — 시크릿 값 기재 금지(위치만)**
> 이 문서는 Public 저장소(`duelspost-droid/darkweb-monitor-dashboard`)에 커밋된다. 비밀번호·API 키·Supabase `service_role`·anon JWT·`SCAN_SECRET`·DB 비밀번호 등 **실제 시크릿 값은 어떤 형태로도 기재하지 않는다.** 변수 이름과 보관 위치만 적고, 값이 필요한 자리는 `{URL}`, `{ANON}` 같은 플레이스홀더로 표기한다.

---

## 1. 개요

JB금융그룹 4개 계열사 도메인(`jbfg.com`·`jbbank.co.kr`·`kjbank.com`·`wooricap.com`) 계정의 **다크웹/유출/인포스틸러 노출**을 매일 자정(KST) 자동으로 조회해, 관리자 인증 후에만 접근 가능한 비공개 대시보드에 표시하는 도구다.

- **스택**: Next.js 16(App Router, 정적 export) + TypeScript + Tailwind 3 + lucide-react + Supabase(DB/Auth/Edge Function/pg_cron) + `@supabase/supabase-js`
- **개발 기간**: 2026-06-21 ~ 06-25 (5일). 데모 정적 대시보드 → Supabase 풀스택 백엔드 → 멀티소스 인텔리전스 → 인증/RLS 비공개화 → 커스텀 도메인 → 조치(remediation) 워크플로 순으로 진화.
- **진화 흐름**: 데모 → Supabase 백엔드 → 4도메인 확정 → Cavalier 인포스틸러 → 관리자인증/RLS → 비번 단독 로그인 → 멀티소스 확장 → 커스텀 도메인 → 운영 하드닝 → 조치 워크플로
- **데이터 원칙(핵심)**: 다크웹 직접 크롤링·덤프 다운로드 **금지**. 합법 유출 인텔리전스 API 조회만 사용. 평문 비밀번호 미저장. 계정은 기본 마스킹 저장(회사 소유 계정만 인증 후 식별 표시).

---

## 2. 현재 라이브 상태 (URL)

| 대상 | URL | 상태(curl 실측) |
|------|-----|------|
| **라이브 대시보드(커스텀 도메인)** | https://dark.jbax.co.kr/ | **200** (정상) |
| GitHub Pages 프로젝트 경로 | https://duelspost-droid.github.io/darkweb-monitor-dashboard/ | 301 (커스텀 도메인으로 리다이렉트) |
| github.io 루트 | https://duelspost-droid.github.io/ | 404 (정상 — 프로젝트 사이트만 존재) |
| 플레이그라운드 슬롯 | https://www.jbax.co.kr/ | 200 (‘다크웹 유출 모니터링’ 카드가 위 대시보드로 링크. 별도 repo `duelspost-droid/jbax-www`, master) |

- **접근 게이트**: Supabase Auth 로그인(이메일+비밀번호) + RLS. 비로그인 상태에서는 데이터가 노출되지 않는다.
- **RLS 잠금 라이브 검증 완료**: anon 키로 `GET /rest/v1/breach_findings?select=finding_id` 호출 시 HTTP 200이지만 응답 본문이 빈 배열 `[]`. authenticated(로그인) 세션만 SELECT 허용(005 마이그레이션) 실측 확인. (키 값은 미기재.)

---

## 3. 아키텍처 / 데이터 흐름

```
[수집 — 서버 / 자정 배치]
  Supabase pg_cron  'daily-breach-scan'  ('0 15 * * *' = 15:00 UTC = 00:00 KST)
      │  pg_net (net.http_post), URL·시크릿은 Vault(decrypted_secrets)에서 읽음
      ▼
  Edge Function  scan-breaches  (Deno)   ── verify_jwt=false + x-scan-secret 헤더 검사
      │  합법 유출 인텔 API 조회 (다크웹 직접 크롤링 없음)
      │   ├─ 주(primary, 택1):  HIBP(키) │ XposedOrNot(무료) │ 둘 다 없으면 no_source
      │   └─ 보조(항상 시도):   IntelX │ LeakCheck │ Hudson Rock Cavalier │ GitHub │ ProxyNova COMB
      ▼
  Supabase DB (Postgres + RLS)
    breach_findings · scan_runs · infostealer_findings · infostealer_hosts · remediation_log
    (계정 마스킹 저장 / 평문 비번 미저장 / status는 upsert 미포함이라 기존 조치상태 보존)

[배포 — CI]
  GitHub Actions  deploy.yml  (push main │ 수동 │ schedule '30 15 * * *' = 00:30 KST)
      │  npm ci → supabase:pull (RLS로 빈값, continue-on-error) → next build (static export)
      ▼
  GitHub Pages  →  https://dark.jbax.co.kr/   (public/CNAME 존재 → 루트 배포)

[열람 — 클라이언트]
  app/page.tsx (얇은 서버 래퍼, 데이터 미포함)
      ▼
  app/DashboardClient.tsx ("use client")
      │  Supabase Auth signInWithPassword → 세션으로 RLS 통과
      ▼
  4개 테이블 병렬 fetch (breach_findings, scan_runs, infostealer_findings, infostealer_hosts)
      → 클라이언트에서 BreachScan 조립·집계·정렬·렌더
      → 조치(remediation): supabase.rpc("set_remediation", {p_account, p_status, p_note})
```

**핵심 분리**: 스캔(데이터 수집)은 CI가 아니라 Supabase Edge Function + pg_cron(15:00 UTC)이 수행한다. CI는 30분 뒤(15:30 UTC) 그 결과를 `supabase:pull`로 읽어와 정적 빌드만 한다. 정적 산출물에는 실데이터가 들어가지 않으며, 실데이터는 런타임에 로그인 후 Supabase에서만 받는다.

---

## 4. 인프라 / 자격증명 (값 제외 · 위치만)

> 아래는 **이름과 보관 위치만**이다. 실제 값은 어디에도 기재하지 않는다.

| 항목 | 위치 | 비고 |
|------|------|------|
| Git origin | `git@github.com:duelspost-droid/darkweb-monitor-dashboard.git` | Public repo, 브랜치 `main` |
| Supabase 프로젝트 | ref `elaoeffpzrswpdpfuoil` · URL `https://elaoeffpzrswpdpfuoil.supabase.co` | 리전 Seoul(ap-northeast-2), Free 플랜 |
| `.env.local` (gitignore) | 로컬 | `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY` (값 미노출) |
| `.env.production` (커밋됨) | repo | `NEXT_PUBLIC_ADMIN_EMAIL=duels@jbfg.com`만 — 비밀 아님(게이트는 비밀번호). Supabase URL/anon은 여기 두지 않음 |
| GitHub Actions Secrets | GitHub | `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY` (Edge 자동배포 설정 시 추가로 `SUPABASE_ACCESS_TOKEN`) |
| Supabase Edge Function Secrets | Supabase | `SCAN_SECRET`, `MONITORED_EMAILS`, `MONITORED_DOMAINS` (+옵션 `HIBP_API_KEY`/`INTELX_API_KEY`/`LEAKCHECK_API_KEY`/`GITHUB_TOKEN`) |
| Supabase Vault | Supabase | `project_url`, `scan_secret` (pg_cron이 읽음 — 마이그레이션에 평문 없음) |
| DB 비밀번호 / `service_role` / anon JWT / `SCAN_SECRET` 값 | 별도 안전 보관 | **문서·코드 어디에도 없음** |

> 참고: anon 키는 공개되어도 데이터는 RLS(로그인 필요)로 보호된다는 게 설계 전제다. `service_role` 키는 절대 클라이언트에 노출하지 않는다.

---

## 5. 데이터 소스 (전체)

수집 로직은 두 곳에 거의 동일하게 구현돼 있다.
- 로컬/CI: `scripts/monitor_breaches.mjs` (Node, 결과를 파일 + 선택적 Supabase upsert)
- 서버 자정배치: `supabase/functions/scan-breaches/index.ts` (Deno Edge, pg_cron 호출, Supabase REST 직접 적재)

### 5.1 주(primary) 소스 — 택1 (우선순위)

| 소스 | 무료/유료 | 키(이름만) | 비고 |
|------|----------|-----------|------|
| **HIBP (Have I Been Pwned)** | 유료(+도메인 소유검증) | `HIBP_API_KEY` (헤더 `hibp-api-key`) | 도메인 전수 검색. 마스킹 계정 + 유출명 + 노출항목 분류(한글) + severity 저장. 평문 미저장 |
| **XposedOrNot** | 무료(키 불필요, 실데이터) | (없음) | 계정별 조회. 무료 레이트 배려 350ms sleep |

키·계정 둘 다 없으면 `status="no_source"`로 수집을 건너뛴다(데모/가짜 데이터를 만들지 않음).

### 5.2 보조 소스 — 항상 추가 시도 (키 게이트 / 무료 토글)

| 소스 | 무료/유료 | 키(이름만) | 저장 내용 | 키 없을 때 |
|------|----------|-----------|-----------|-----------|
| **Intelligence X** | 유료(키) | `INTELX_API_KEY`(헤더 `x-key`), `INTELX_API_HOST`(기본 `2.intelx.io`), `INTELX_BUCKETS`(선택) | 도메인 단위 레코드명·bucket·날짜 → severity/분류 추론. 평문 없음 | skip |
| **LeakCheck** | 키=유료(Pro v2) / 무키=무료(public) | `LEAKCHECK_API_KEY`(헤더 `X-API-Key`) | source명·날짜 + `fields`(분류만). **password 등 평문은 매핑에서 제외**, 분류만 한글화 | 키 없으면 계정명부 있을 때 public 모드, 그것도 없으면 skip |
| **Hudson Rock Cavalier (계정별)** | 무료 OSINT | (키 없음) 토글 `HUDSONROCK_OSINT_ENABLED`(기본 1) | breach_finding(자격증명/비밀번호/인포스틸러 감염) + **호스트 상세**(PC명·OS·부분마스킹 IP·감염일·스틸러 종류·백신·부분마스킹 top_passwords/top_logins). 평문 아님 | 토글 0이면 skip |
| **GitHub 공개 노출** | 무료(합법, PAT 필요) | `GITHUB_TOKEN`(헤더 `Bearer`) | repo·파일경로·html_url **포인터만**(자격증명 값 미저장), severity=high | skip |
| **ProxyNova COMB** | 무료 키리스(합법 공개) | (없음) | `email:password` 라인에서 **우측 평문 비번 폐기**, 계정만. `plausibleEmail()` + 정확한 `@domain` 접미사 가드로 잡음 제거. breachName="COMB 통합본", 분류=[이메일,비밀번호] | (무료라 항상 동작, 도메인 있을 때만) |

추가로 **Hudson Rock Cavalier 도메인 전수**(`search-by-domain`, 무료)는 `infostealer_findings`로 별도 집계(total/employees/users/third_parties + affected_urls 상위 30개).

### 5.3 멀티소스 동작 규칙

- 보조 소스는 키 없으면 `used:false` 반환 → 병합 안 함(전체 스캔은 계속). Edge Function에서 보조 소스 예외는 try/catch로 격리해 전체 스캔을 죽이지 않음(500 방지).
- 견고한 `fetchJson`: 429/5xx는 Retry-After/지수백오프 재시도, 실패해도 throw 안 함.
- **provenance(출처) 이중 기록**: finding마다 `source` 라벨 + 스캔 전체 `sources[]` 배열(`{name, kind('breach'|'infostealer'), endpoint, count, scannedAt}`). `scan_runs.sources`(JSONB)에 저장 → pull 스크립트가 정적 사이트로 전달.

### 5.4 교차매핑 (유출 ∩ 인포스틸러)

- `collectProxynovaComb`가 도메인 노출 계정 집합을 만든 뒤, 두 보강을 **Promise.all 병렬** 실행 — (a) 유출이력(LeakCheck public + XposedOrNot), (b) 인포스틸러 교차(`collectCavalierAccounts`). 같은 계정의 유출+인포스틸러 finding이 한 스캔에 같이 적재됨.
- UI(DashboardClient)는 finding을 `accountMasked` 기준으로 그룹핑하고, `source`가 Hudson Rock이거나 dataClasses에 “인포스틸러 감염”이 포함되면 `hasStealer=true` → 그룹을 최상단 정렬 + ‘🔴 유출+인포스틸러’ 배지 + 조치 컨트롤 표시.

---

## 6. 모니터링 대상 도메인

공개 설정(`data/security/monitor_config.json`)의 JB금융 4개 계열사:

| 도메인 | 계열사 |
|--------|--------|
| `jbfg.com` | JB금융지주 |
| `jbbank.co.kr` | 전북은행 |
| `kjbank.com` | 광주은행 |
| `wooricap.com` | JB우리캐피탈 |

- `monitor_config.json`의 `accounts`는 **빈 배열**. 개별 이메일은 gitignore된 `monitor_config.local.json`(또는 `*.local.json`)과 Edge Secret `MONITORED_EMAILS`에만 존재.
- DB 이중방어: 마이그레이션 007이 `breach_findings`·`infostealer_findings`·`infostealer_hosts`의 `domain`을 위 4개로 CHECK 제약(앱 가드 + DB 제약).

---

## 7. 인증 / 접근 제어

- **로그인 게이트**: Supabase Auth(이메일+비밀번호). 세션이 없으면 `LoginGate`, 데이터는 로그인 후에만 조회(RLS).
- **고정 관리자 이메일**: `NEXT_PUBLIC_ADMIN_EMAIL`(=`duels@jbfg.com`)이 설정돼 있으면 로그인 폼이 **비밀번호만** 받음(이메일 입력 숨김). ‘다른 계정으로 로그인’ 토글로 이메일 입력 노출 가능. 식별자는 번들에 노출되지만 게이트는 비밀번호다.
- **비밀번호 설정/변경**: 초대/재설정 링크(URL에 `type=recovery|invite`) 또는 `onAuthStateChange`의 `PASSWORD_RECOVERY` 이벤트 → `SetPasswordPanel` 강제(취소 불가). 로그인 상태에서는 상단 ‘비밀번호 변경’ 버튼으로 수동 변경(취소 가능). 성공 후 `window.history.replaceState`로 URL의 토큰 흔적 제거.
- **관리자 비밀번호는 본인이 메일 링크로 설정한다. AI는 비밀번호를 설정하지 않는다(정책).**
- **RLS**: 005 마이그레이션에서 `breach_findings`·`scan_runs`·`infostealer_findings`의 SELECT를 authenticated 전용으로 잠금(이전 001/002/004는 USING true 공개였음). `infostealer_hosts`(006)·`remediation_log`(008)는 처음부터 authenticated. 쓰기는 전부 `service_role` 전용.
- **조치 RPC**: `set_remediation(p_account, p_status, p_note)` — SECURITY DEFINER, authenticated만 EXECUTE. 상태변경 + 감사로그 적재를 원자적으로 수행. status는 `open|remediated|dismissed`만 허용, actor는 `auth.jwt()->>'email'`.

> **마스킹 정책 정정 메모(중요)**: 타입/주석상 ‘항상 마스킹(`accountMasked`)’이라 적혀 있으나, **마이그레이션 005**가 `breach_findings.account`(full, 비마스킹) 컬럼을 추가했고 RLS로 authenticated만 조회 허용한다. Edge Function의 `mkFinding`/`mkRawFinding`가 이 컬럼을 채우며(로컬 mjs는 안 채움), `fetchScan`은 `r.account || r.account_masked`로 **식별(full) 값 우선** 표시하고 UI에 ‘식별 표시’ 배지를 단다. 즉 "회사 소유 계정 한정, 인증 후 식별 표시"가 정확한 서술이다.

---

## 8. 파일 구조

```
darkweb-monitor-dashboard/
├─ app/
│  ├─ page.tsx                     # 얇은 서버 래퍼 (DashboardClient만 렌더, 데이터 미포함)
│  ├─ DashboardClient.tsx          # "use client" — 로그인 게이트 + fetch + 전체 대시보드 렌더
│  └─ layout.tsx                   # lang="ko", 상단바 브랜드, content-shell
├─ components/ui/
│  ├─ PageHero.tsx                 # 그라디언트 히어로
│  ├─ Panel.tsx                    # 카드 컨테이너
│  ├─ StatTile.tsx                 # KPI 타일
│  └─ BarList.tsx                  # 수평 바 분포
├─ lib/
│  ├─ supabase/browserClient.ts    # createClient(url, anon), supabaseConfigured, adminEmail
│  ├─ types/breachMonitor.ts       # BreachScan 등 타입(마스킹 원칙 주석)
│  └─ data/generated/breachMonitor.ts  # pull이 생성하는 빈 스텁(현재 미사용, 편집 금지)
├─ scripts/
│  ├─ monitor_breaches.mjs         # 로컬/CI 수집기 (security:scan)
│  ├─ pull_from_supabase.mjs       # Supabase → 생성파일 동기화 (supabase:pull)
│  └─ check_employee_stealers.mjs  # 내부전용 임직원 점검 (security:employee, 결과 gitignore)
├─ supabase/
│  ├─ config.toml                  # project_id, [functions.scan-breaches] verify_jwt=false
│  ├─ functions/scan-breaches/index.ts   # Deno Edge Function (자정 배치)
│  └─ migrations/
│     ├─ 001_breach_monitoring.sql # 기본 스키마(breach_findings, 마스킹 저장)
│     ├─ 002_backend.sql           # 백엔드 확장(scan_runs 등)
│     ├─ 003_cron.sql              # pg_cron 자정 스캔
│     ├─ 004_infostealer.sql       # infostealer_findings + sources(provenance)
│     ├─ 005_admin_only.sql        # 공개읽기 제거(authenticated SELECT) + account(full) 컬럼
│     ├─ 006_infostealer_hosts.sql # 감염 호스트 상세(authenticated)
│     ├─ 007_domain_whitelist.sql  # domain 4개 CHECK 제약
│     └─ 008_remediation.sql       # status/메모 컬럼 + remediation_log + set_remediation RPC
├─ data/security/monitor_config.json   # 공개: domains 4개(accounts 빈 배열)
├─ public/CNAME                    # dark.jbax.co.kr
├─ docs/
│  ├─ HANDOFF.md                   # (이 문서)
│  ├─ CI_DEPLOY_SETUP.md           # Edge 함수 자동배포(deploy-edge.yml) 가이드 — 미적용
│  └─ DARKWEB_TOR_CRAWLER_DESIGN.md# Tor 크롤러 설계/거버넌스 v1.0 — 미구현
├─ .github/workflows/deploy.yml    # Scan and Deploy (CI)
├─ next.config.mjs                 # CNAME 유무로 basePath 결정, export 모드 토글
├─ package.json                    # 스크립트/engines node>=20
├─ .env.example / .env.production  # 변수 카탈로그 / ADMIN_EMAIL
└─ .gitignore                      # .env*, *.local.*, internal-tools/ 등
```

> gitignore로 비커밋: `.env`/`.env.local`/`.env.*.local`, `data/security/*.local.json`·`*.local.*`(모니터링 이메일·내부 리포트), 로컬 스캔 산출물(`latest_breach_scan.json`, `history/`), `internal-tools/`(망분리 전용 IR 도구), `node_modules`/`.next`/`out` 등 표준.

---

## 9. 로컬 개발 (`--webpack` 등)

- **node가 PATH에 없음** — Codex.app 번들 node 사용(별도 우회 필요).
- **로컬 dev/build는 `-- --webpack` 필수**: Codex.app 번들 node로 설치한 `@next/swc-darwin-arm64` 네이티브 바인딩이 코드서명 Team ID 불일치로 로드 거부됨 → Next 16 기본 Turbopack 실패. CI(정식 node 24)에선 불필요.
- 정적 export 로컬 빌드 예:
  ```bash
  NEXT_OUTPUT=export PAGES_BASE_PATH=/darkweb-monitor-dashboard npm run build -- --webpack
  ```
- npm 스크립트(`package.json`, `engines.node >=20.0.0`, `type: module`):
  - `dev` = `next dev`
  - `build` = `next build`
  - `start` = `next start`
  - `typecheck` = `tsc --noEmit`
  - `security:scan` = `node scripts/monitor_breaches.mjs`
  - `security:employee` = `node scripts/check_employee_stealers.mjs`
  - `supabase:pull` = `node scripts/pull_from_supabase.mjs`

---

## 10. 배포 / 운영

### CI 워크플로 (`.github/workflows/deploy.yml`, 이름 `Scan and Deploy`)

- **트리거**: `push`→`main` · `workflow_dispatch`(수동) · `schedule` cron `"30 15 * * *"` (15:30 UTC = **00:30 KST**, Supabase 자정 스캔 직후 반영).
- **권한**: `contents: write`(스냅샷 자동커밋), `pages: write`, `id-token: write`. concurrency `pages`, `cancel-in-progress: false`.
- **build 잡**(ubuntu-latest): checkout(@v6) → Setup Node 24(@v6) → `npm ci` → `npm run supabase:pull`(timeout 5분, `continue-on-error: true`; 잡 env로 `NEXT_PUBLIC_SUPABASE_URL`·`NEXT_PUBLIC_SUPABASE_ANON_KEY` 주입) → 스냅샷 자동커밋(`git-auto-commit-action@v7`, 대상 `lib/data/generated/breachMonitor.ts`, 메시지 "Update dashboard snapshot from Supabase") → `npm run build`(env `NEXT_OUTPUT=export`, `PAGES_BASE_PATH=/darkweb-monitor-dashboard`) → configure-pages(@v6) → upload-pages-artifact(@v5, `./out`).
- **deploy 잡**: `needs: build`, environment `github-pages`, `deploy-pages@v5`.
- CI가 참조하는 시크릿은 `NEXT_PUBLIC_SUPABASE_URL`·`NEXT_PUBLIC_SUPABASE_ANON_KEY` **2개뿐**.

### 커스텀 도메인 / basePath (`next.config.mjs`, `public/CNAME`)

- `public/CNAME` = `dark.jbax.co.kr`. `next.config.mjs`가 `existsSync("public/CNAME")`로 판단:
  - CNAME 존재 → `base = ""`(루트 배포, basePath 없음).
  - 없으면 → `base = process.env.PAGES_BASE_PATH || ""`.
- export 모드(`NEXT_OUTPUT === "export"`)일 때만 `output: "export"` + `basePath`/`assetPrefix` + `images.unoptimized: true` 적용. `reactStrictMode: true` 항상.
- **현재 CNAME이 존재하므로 CI에서 `PAGES_BASE_PATH`를 넘겨도 basePath는 빈값(루트)으로 동작**한다.

### Edge Function 배포

- 현재 `scan-breaches`는 Supabase 대시보드에서 **수동 배포**. `docs/CI_DEPLOY_SETUP.md`가 자동배포용 `deploy-edge.yml` 추가법을 안내하나 **아직 미적용**(파일 미생성). 자동배포 시 `SUPABASE_ACCESS_TOKEN` 레포 시크릿 등록 + `supabase functions deploy scan-breaches --project-ref <ref> --no-verify-jwt` 필요. Claude gh 토큰에 `workflow` 스코프가 없어 `.github/workflows/` 파일은 사용자가 직접 추가해야 함.

---

## 11. 작업 이력 (커밋 묶음, 시간순)

자동 커밋 "Update dashboard snapshot from Supabase"는 제외. 의미 단위 커밋만(오래된→최신).

### 1단계 — 초기 데모 대시보드 (06-21)
- `6d09697` 신규 독립 프로젝트: Next.js 정적 대시보드 + 데모 데이터 + UI 컴포넌트(PageHero/Panel/StatTile/BarList) + 로컬 수집기 `monitor_breaches.mjs` + 001 스키마(HIBP 전제)
- `5bf789b` 이어작업용 HANDOFF + CLAUDE.md 문서 추가

### 2단계 — Supabase 백엔드 전환 + 실데이터 (06-22)
- `952ecf9` **핵심 전환점**: Supabase 백엔드(Edge Function `scan-breaches` + pg_cron 자정 스캔), XposedOrNot 실데이터 연동, 대시보드 동기화(`pull_from_supabase.mjs`), 002/003 마이그레이션
- `c82177c` 모니터링 대상을 **JB금융 4개 계열사 도메인**으로 확정
- `aa21cbd` **Hudson Rock Cavalier** 도메인 전수 인포스틸러 수집 + provenance(`sources[]`) 기록, 004 마이그레이션

### 3단계 — 관리자 인증 + 비공개화 (06-22~23)
- `4ddd8c7` **관리자 인증(Supabase Auth) 비공개 대시보드 + RLS 잠금**: `DashboardClient.tsx` 신설, 정적 빌드에서 실데이터 제거(generated 빈 placeholder화), 005 마이그레이션(SELECT=authenticated), 내부전용 `check_employee_stealers.mjs` 추가
- `4140d83` 초대/재설정 링크 진입 시 비밀번호 설정 폼 표시 fix(PASSWORD_RECOVERY 처리)
- `704fb7f` 비밀번호 단독 관리자 로그인(고정 관리자 이메일 시 비번만 입력)

### 4단계 — 유출 소스 확장 + UX 재설계 (06-23)
- `d70dec0` 유출 소스 확장: Hudson Rock 계정별 + IntelX + LeakCheck + HIBP 전수 하드닝
- `b2ee533` 인포스틸러 점검 설명 + 감염 호스트 상세, 006 마이그레이션(infostealer_hosts)
- `95a0cad` 더미데이터 제거 + 대시보드 상세 재디자인(refactor)
- `17a622c` / `5c79108` 모바일 반응형(상단 wrap + 테이블 카드뷰) + 가로 오버플로 fix
- `08f9cde` 인포스틸러 상황 해석 + 대응 가이드 + 탈취 페이지 상세
- `853d081` / `e39ac74` / `75d931e` GitHub 공개노출 검색 콜렉터(무료·합법) + 정밀쿼리 노이즈 축소 + Edge 500 방지(보조소스 try/catch 격리)
- `07bc6da` breach_findings 적재 PGRST102 오류 fix(행 키 정규화)

### 5단계 — 커스텀 도메인 + COMB 보강 (06-23~24)
- `079117c` **커스텀 도메인 dark.jbax.co.kr**(public/CNAME, CNAME 존재 시 루트 배포)
- `2ea0ad4` 유출 계정 상세 마스킹 제거(회사 소유 계정 관리자 식별 표시)
- `122c307` **ProxyNova COMB** 콤보리스트 수집기(무료 키리스)
- `fb3083e` / `ea24fb1` / `d1e3a13` COMB 노출계정에 유출이력(언제/어디서) 보강 + XposedOrNot 유출이력 추가 + 출처/날짜 명시 + COMB 계정 정합성 검증(URL조각·형식오류 제거)
- `980a300` 유출 계정 상세 — 계정별 그룹뷰
- `914d426` 유출 ∩ 인포스틸러 교차 매핑

### 6단계 — 운영 하드닝 + Tor 설계 + 문서 (06-24~25)
- `d2a7031` 스캔 병렬화·레이트리밋·**도메인 화이트리스트**(007) + CI 배포 문서(`docs/CI_DEPLOY_SETUP.md`)
- `2c67cff` / `c80c35a` 다크웹(Tor) 모니터링 종합 설계·거버넌스 문서 v1.0(설계만, 미구현)
- `57cc3dc` `internal-tools/` gitignore화(망분리 내부 IR 도구 비커밋, chore)
- `1d8c158` / `13a63b3` 개발용 종합 핸드오프 갱신 및 현재 상태 정합화(docs)

### 7단계 — 조치 워크플로 (최신, 06-25)
- `15593bb` **조치(remediation) 워크플로**: 008 마이그레이션 — `breach_findings`에 `status`/`remediation_note`/`remediated_at`/`remediated_by` 컬럼 + `remediation_log`(append-only 감사로그) + `set_remediation()` RPC(authenticated, SECURITY DEFINER). 대시보드에 계정 그룹별 조치 컨트롤(상태버튼·자동 조치의견·메모) + 조치내역 패널. 자정 재스캔은 status 미포함 upsert라 기존 조치상태 보존.

> 커밋 총 65개 중 자동 snapshot 제외 의미 커밋 33개(feat/fix/docs/chore/refactor). 현재 HEAD = `15593bb`, `origin/main`과 동기화(ahead 0/behind 0), 워킹트리 클린.

---

## 12. 보안 · 개인정보 원칙 (코드로 강제)

- **다크웹 직접 크롤링·덤프 다운로드 금지** — 합법 유출 인텔 API 조회만.
- **계정은 기본 마스킹**(`account_masked`, 예 `jo***@domain`) 저장. **회사 소유 계정만 인증 뒤 식별(full, `account` 컬럼) 표시**(005, RLS authenticated 전용).
- **평문 비밀번호·전체 이메일·토큰 값 미저장** — 노출 "항목 분류"만 저장. COMB은 우측 평문 비번 폐기, LeakCheck는 password 필드를 매핑에서 제외, GitHub은 포인터(URL)만.
- **고객 개인식별/평문비번 미구축** — 집계(감염 건수) + 영향 URL까지만.
- **호스트 상세**(infostealer_hosts)는 민감 → RLS authenticated 전용. IP/top_passwords는 Hudson Rock이 이미 부분 마스킹한 값만 보관·표시. UI에 "화면 캡처·외부 공유 금지" 경고.
- **임직원 개별 점검**(PC명·부분IP·부분비번)은 로컬 내부 전용(`security:employee`) → `employee_stealer_report.local.json`(gitignore). git/Supabase/공개 금지(파일 헤더 명시).
- **내부망 IR 도구**는 `internal-tools/`로 gitignore(비커밋, 망분리 보호망 이전).
- **stale 정리**: 매 스캔마다 `last_scan_tag` 부여 후 이번 태그가 아닌 행을 DELETE → 현재 노출만 유지. status는 upsert payload에 미포함이라 merge-duplicates가 기존 조치상태 보존.

---

## 13. 미완 / 다음 TODO

- [ ] **관리자 비밀번호 설정 완료 미확인** — `duels@jbfg.com`이 메일 링크로 본인 설정 필요(AI 미수행). Supabase 무료 SMTP 한도로 초대/재설정 메일이 안 올 수 있음. 로그인 동작 최종 확인.
- [ ] **보조 소스 키 활성화** — IntelX/LeakCheck/GitHub/HIBP 코드는 구현 완료, 키만 Edge Secret에 넣으면 자정 배치 적용(현재 키 없어 skip 추정). 각 소스 라이브 결과 검증.
- [ ] **Edge 함수 CI 자동배포 미구성** — `deploy-edge.yml` 미생성(사용자가 직접 추가 + `SUPABASE_ACCESS_TOKEN` 시크릿 등록). 현재는 Supabase 대시보드 수동 배포.
- [ ] **Tor 다크웹 크롤러 미구현** — 설계/거버넌스 문서만(`docs/DARKWEB_TOR_CRAWLER_DESIGN.md`, ~26KB). 법무·망분리 검토 후 구현. 설계상 단계적 진입 게이트(Phase 0 클리어넷 → Phase 1 .onion은 형사 적법성 의견서 + 평문/링크 차단 코드 + stale-delete tier 격리 + 키셋 정합화 4종 충족 전 금지).
- [ ] **알림/보고서** — 신규 발견 Slack/메일 웹훅 + 보고서 자동 이메일(Resend 등 키 필요).
- [ ] **스캔 이력 보존 정책** 수립 + 인포스틸러 추이 차트.
- [ ] **로컬 mjs / Edge Function 소스 로직 중복**(2벌 동기 유지 부담) — 공유 모듈 추출 검토.

---

## 14. 알려진 이슈 / 주의

- **로컬 빌드 제약**: node가 PATH에 없음(Codex.app 번들) + `--webpack` 필수(SWC 네이티브 코드서명 Team ID 불일치). CI(정식 node 24)는 Turbopack 정상.
- **CNAME 존재 시 basePath 무시**: `public/CNAME`(dark.jbax.co.kr)이 있는 한 `PAGES_BASE_PATH`는 무시되고 루트 배포. 커스텀 도메인 제거 시 basePath 동작 재확인 필요.
- **마스킹 서술 정정 필요**: ‘항상 마스킹’ 주석과 달리 인증 후 `fetchScan`은 `account`(full) 우선 표시(회사 소유 계정 한정, ‘식별 표시’ 배지). 문서·정책에 이 예외를 명문화할 것(7절 참조).
- **CLAUDE.md 데이터흐름 불일치**: CLAUDE.md는 `app/page.tsx → breachScan import 후 서버 렌더`라 기술하나, 실제는 import하지 않고 클라이언트 Supabase fetch로 전환됨. `lib/data/generated/breachMonitor.ts`는 빈 스텁이며 어디서도 import되지 않음(grep 확인). 이 차이를 정리/수정 권장.
- **미사용 생성 스텁**: `lib/data/generated/breachMonitor.ts`의 용도 결정 필요(정적 폴백으로 쓸지/삭제할지).
- **DNS/HTTPS**: dark.jbax.co.kr는 현재 200으로 실동작 중. (구 HANDOFF TODO에 DNS 등록/Pages HTTPS 검증이 미체크로 남아 있었으나 실측상 정상.)
- **Tor 설계 문서 주의사항**: 대시보드 "무변경" 주장은 철회됨 — 평문 `account` 우선 렌더·`reference_url` 무조건 링크 렌더는 .onion 단계 진입 전 수정 대상으로 설계에 명시.

---

## 15. 검증 명령

```bash
# --- 라이브 상태 (값 노출 없음) ---
curl -sS -o /dev/null -w "%{http_code}\n" https://dark.jbax.co.kr/                 # 기대: 200
curl -sS -o /dev/null -w "%{http_code}\n" https://www.jbax.co.kr/                  # 기대: 200 (플레이그라운드)

# --- RLS 잠금 검증: anon으로는 빈 배열이어야 함 (anon 키 값은 노출 금지) ---
curl -sS "https://elaoeffpzrswpdpfuoil.supabase.co/rest/v1/breach_findings?select=finding_id" \
  -H "apikey: {ANON}" -H "Authorization: Bearer {ANON}"                            # 기대: HTTP 200 + 본문 []

# --- Git / 마이그레이션 / 설정 ---
git -C /Users/hk/darkweb-monitor-dashboard status -sb                              # 기대: ## main...origin/main (clean)
ls /Users/hk/darkweb-monitor-dashboard/supabase/migrations/                        # 기대: 001~008 8개
cat /Users/hk/darkweb-monitor-dashboard/public/CNAME                               # 기대: dark.jbax.co.kr

# --- 타입 체크 / 로컬 정적 빌드 (로컬은 --webpack 필수) ---
cd /Users/hk/darkweb-monitor-dashboard && npm run typecheck
NEXT_OUTPUT=export PAGES_BASE_PATH=/darkweb-monitor-dashboard npm run build -- --webpack

# --- Supabase pull (RLS로 빈값 반환, 정상) ---
cd /Users/hk/darkweb-monitor-dashboard && npm run supabase:pull
```

> 위 명령에 등장하는 Supabase URL/ref는 이미 공개된 식별자다. anon/`service_role` JWT, `SCAN_SECRET`, DB 비밀번호 등 **실제 시크릿 값은 명령·출력 어디에도 포함하지 않는다**(`{ANON}` 등 플레이스홀더만 사용).
