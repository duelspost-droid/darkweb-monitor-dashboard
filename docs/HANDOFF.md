# 작업 핸드오프 — 다크웹 유출 모니터링 대시보드

> 다음 세션/개발자가 바로 이어서 개발하기 위한 종합 기록. (최종 갱신: 2026-06-25)
> ⚠️ 이 파일은 **공개 GitHub repo**에 커밋됩니다. **시크릿 값(비밀번호·키·service_role·SCAN_SECRET 등)은 절대 기재 금지** — 보관 위치만 표기.

## 1. 프로젝트 개요
- **이름**: `darkweb-monitor-dashboard` (Credential Leak Monitor)
- **목적**: JB금융그룹 계열사 도메인 계정이 다크웹/유출 데이터셋·인포스틸러 로그에 노출됐는지 **매일 자정 자동 조회**하고, **관리자 인증 후** 대시보드에 표시.
- **스택**: Next.js 16(App Router, 정적 export) · TypeScript · Tailwind · lucide-react · **Supabase**(DB·Auth·Edge Function·pg_cron) · @supabase/supabase-js
- **데이터 원칙**: 다크웹 직접 크롤링 금지 — 합법 유출 인텔리전스 API만. 평문 비밀번호 미저장.

## 2. 현재 라이브 상태 (✅ 배포 완료)
- **대시보드(공개 URL, 관리자 인증 게이트)**: https://duelspost-droid.github.io/darkweb-monitor-dashboard/
  - 로그인 전엔 데이터 안 보임(RLS). 로그인 후 식별 데이터 표시.
- **플레이그라운드 슬롯**: https://www.jbax.co.kr/ 의 "다크웹 유출 모니터링" 카드 → 위 대시보드로 링크 (repo: `duelspost-droid/jbax-www`, master).
- **GitHub repo**: https://github.com/duelspost-droid/darkweb-monitor-dashboard (Public). Pages: Source=GitHub Actions.
- **현재 실데이터**: 계정 유출 1건(`webmaster@jbbank.co.kr`, Epik) · 인포스틸러 819건(kjbank 464·jbbank 282·wooricap 73·jbfg 0).

## 3. 아키텍처 / 데이터 흐름
```
[매일 자정] pg_cron(15:00 UTC=KST 자정) → net.http_post → Edge Function `scan-breaches`
   → XposedOrNot(계정별) + HIBP(옵션) + Hudson Rock Cavalier(도메인 전수 인포스틸러)
   → Supabase: breach_findings / infostealer_findings / scan_runs (마스킹/집계 저장)
[대시보드] app/page.tsx → app/DashboardClient.tsx ("use client")
   → Supabase Auth 로그인 → 세션으로 RLS 통과 → 3개 테이블 직접 fetch → 렌더
   ※ 정적 빌드에는 실데이터 미포함(lib/data/generated/breachMonitor.ts 는 빈 placeholder)
[CI] .github/workflows/deploy.yml (15:30 UTC + push) → npm ci → supabase:pull(RLS로 빈값) → 빌드 → Pages 배포
```

## 4. 인프라 / 자격증명 (값은 안전한 곳에 보관, 여기엔 위치만)
- **Supabase 프로젝트**: ref `elaoeffpzrswpdpfuoil` · URL `https://elaoeffpzrswpdpfuoil.supabase.co` · 리전 Seoul(ap-northeast-2) · org "duelspost-droid's Org"(Free).
- **CLI**: `/Users/hk/.local/bin/supabase` (미로그인 상태). 대시보드 작업은 브라우저로 수행해 왔음(자세히는 12절 메모리).
- **시크릿 보관 위치**:
  - Supabase **Edge Function Secrets**: `SCAN_SECRET`, `MONITORED_EMAILS`, `MONITORED_DOMAINS` (+ `HIBP_API_KEY` 옵션). (Dashboard → Edge Functions → Secrets)
  - Supabase **Vault**: `project_url`, `scan_secret` (pg_cron 용).
  - 로컬 `.env.local`(gitignore): `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`.
  - **GitHub Actions Secrets**: `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`.
  - **DB 비밀번호 / service_role / anon JWT / SCAN_SECRET 값**: 별도 안전 보관(여기 미기재).

## 5. 데이터 소스 (전부 무료)
- **XposedOrNot** `api.xposedornot.com/v1/check-email/{email}` — 계정별 데이터 유출(키 불필요). `/v1/breaches` 카탈로그로 메타 보강.
- **Hudson Rock Cavalier** `cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=` — **도메인 전수 인포스틸러 집계**(키 불필요). 개별 이메일 점검은 `/search-by-email`(내부 도구만).
- **HIBP**(옵션·유료): `HIBP_API_KEY` 있으면 도메인 전수 검색으로 자동 전환.
- 다음 추가 예정: **RapidAPI(BreachDirectory)**, **IntelX** — 둘 다 무료 티어지만 가입/키 필요.

## 6. 모니터링 대상 도메인 (JB금융 4개 계열사)
`jbfg.com`(JB금융지주) · `jbbank.co.kr`(전북은행) · `kjbank.com`(광주은행) · `wooricap.com`(JB우리캐피탈).
- 도메인 목록: `data/security/monitor_config.json` + Supabase 시크릿 `MONITORED_DOMAINS`.
- 무료 계정별 조회 대상 이메일: `data/security/monitor_config.local.json`(**gitignore**) + 시크릿 `MONITORED_EMAILS`.

## 7. 인증 / 접근 제어
- **관리자 로그인**: Supabase Auth `signInWithPassword` (secuday 방식). 게이트 통과해야 데이터 fetch.
- **RLS**: breach_findings / scan_runs / infostealer_findings 의 SELECT = `authenticated`만(005 마이그레이션). anon 키로는 빈 값. service_role(Edge Function)만 쓰기.
- **관리자 계정**: `duels@jbfg.com` (Supabase Auth). 비밀번호는 **초대/재설정 이메일 링크로 본인이 설정**(대시보드의 "비밀번호 설정/변경" 폼). ⚠️ 비번 설정 미완 가능 — 14절 참고.
- 초대 리다이렉트: Auth → URL Configuration → Site URL = 라이브 대시보드 URL.

## 8. 파일 구조 (핵심)
```
app/
  page.tsx                얇은 래퍼 → <DashboardClient/>
  DashboardClient.tsx     ★로그인 게이트 + 비번설정폼 + Supabase fetch + 전체 렌더
  layout.tsx, globals.css
components/ui/            PageHero·Panel·StatTile·BarList
lib/
  supabase/browserClient.ts   anon 클라이언트(브라우저)
  types/breachMonitor.ts      BreachFinding·InfostealerFinding·SourceRecord·BreachScan
  data/generated/breachMonitor.ts  ★빈 placeholder(정적빌드에 실데이터 X)
scripts/
  monitor_breaches.mjs        로컬/CI 수집기(XposedOrNot/HIBP + Cavalier + 출처)
  pull_from_supabase.mjs       Supabase→생성TS (RLS로 빈값; auth 전환 후 사실상 미사용)
  check_employee_stealers.mjs  ★내부 전용: 임직원 계정 개별 인포스틸러 점검(결과 gitignore)
supabase/
  functions/scan-breaches/index.ts   ★Deno Edge Function(verify_jwt=false, x-scan-secret)
  migrations/001~005.sql             스키마·scan_runs·인포스틸러·cron·RLS잠금
  config.toml
.github/workflows/deploy.yml
data/security/monitor_config.json    (+ *.local.json/.local.html 은 gitignore)
```

## 9. 로컬 개발 (중요한 환경 제약)
- **node/npm이 PATH에 없음** → `export PATH=/Applications/Codex.app/Contents/Resources/cua_node/bin:$PATH` (node24, npm11).
- **dev/build는 `--webpack` 필수**: Codex node로 설치한 `@next/swc-darwin-arm64`가 코드서명 Team ID 불일치로 dlopen 거부 → Turbopack 실패. `npm run dev -- --webpack`, `npm run build -- --webpack`. (CI 정식 node는 Turbopack 정상)
- **preview 런처**: `/Users/hk/.claude/launch.json`의 `darkweb` config (sh -c로 PATH+cd+`npm run dev -- --webpack`, port 3000).
- **.env.local** 필요(NEXT_PUBLIC_SUPABASE_URL/ANON_KEY) — 로그인+fetch 동작.
```bash
npm install
npm run typecheck
npm run dev -- --webpack                  # http://localhost:3000 (로그인 게이트)
npm run security:scan                      # 로컬 수집(시크릿 없이 동작, Supabase 적재는 SUPABASE_* 있을 때)
npm run security:employee                  # 내부 전용 임직원 개별 점검(결과 gitignore)
NEXT_OUTPUT=export PAGES_BASE_PATH=/darkweb-monitor-dashboard npm run build -- --webpack
```

## 10. 배포 / 운영
- **자동 수집**: pg_cron `daily-breach-scan` 15:00 UTC → Edge Function. (003 마이그레이션, Vault 시크릿 사용)
- **함수 재배포**: Supabase Dashboard → Edge Functions → scan-breaches → Code → Deploy. (CLI 미로그인이라 브라우저로 해 왔음; index.ts를 base64로 Monaco에 주입 → Deploy)
- **마이그레이션 적용**: 브라우저 SQL Editor에 붙여 실행(한글 주석은 pbcopy가 깨져 ASCII로 변환 후 붙임).
- **대시보드 배포**: main 푸시 또는 15:30 UTC → GitHub Actions → Pages.
- **수동 함수 호출(테스트)**: `POST {URL}/functions/v1/scan-breaches` + 헤더 `x-scan-secret: <SCAN_SECRET>`.

## 11. 작업 이력 (커밋 / 세션 로그)
- `6d09697` 신규 프로젝트(데모 데이터, HIBP 전제)
- `5bf789b` HANDOFF + CLAUDE
- `952ecf9` **Supabase 백엔드**(Edge Function + pg_cron 자정 + XposedOrNot 실데이터 + 대시보드 동기화)
- `c82177c` 모니터링 대상 = **JB금융 4개 계열사 도메인**
- `aa21cbd` **Hudson Rock Cavalier 도메인 전수 인포스틸러 + 수집 출처(provenance) 기록**
- `4ddd8c7` **관리자 인증(Supabase Auth) 비공개 대시보드 + RLS 잠금**(정적빌드 실데이터 제거)
- `4140d83` 초대/재설정 링크 진입 시 **비밀번호 설정 폼** 표시 fix
- (그 사이 CI "Update dashboard snapshot" 자동 커밋 다수)
- 별도: `duelspost-droid/jbax-www` 에 플레이그라운드 슬롯 카드 추가(master).

## 12. 보안 · 개인정보 원칙 (반드시 준수)
- 계정은 기본 **마스킹** 저장. **회사 소유 계정**만 인증 뒤 식별(full) 표시(breach_findings.account).
- **고객(은행 고객) 개인 식별·평문 비밀번호는 미구축** — 개인정보보호법·신용정보법·금융규제·계정탈취 위험. 고객은 **집계(감염 건수)+영향 URL**까지만.
- **공개 페이지엔 실데이터 미노출**(RLS+인증). 정적 빌드/공개 repo에 데이터 안 남김.
- 임직원 개별 점검(PC명·부분IP·부분비번)은 **로컬 내부 전용**(`security:employee`, 결과 gitignore).
- "공개 유지(마스킹 실데이터)"는 사용자 결정이었으나, 인증 전환으로 현재는 로그인 필요. 민감도 커지면 비공개 호스팅 검토.

## 13. 미완 / 다음 TODO
- [ ] **관리자 비밀번호 설정 완료**(14절) — 로그인 동작 최종 확인(로그인 후 화면은 비번 없어 미검증).
- [ ] **RapidAPI(BreachDirectory) · IntelX 소스 추가**(무료 티어, 키 발급 필요) — 같은 패턴(수집기+출처+섹션).
- [ ] HIBP 유료키 도입 시 도메인 전수(계정별→도메인) 자동 전환 검증.
- [ ] 알림(신규 발견 시 Slack/메일 웹훅), 보고서 자동 이메일(Resend 등 키 필요).
- [ ] 스캔 이력 보존 정책, 인포스틸러 추이 차트.
- [ ] (선택) 사용자 메일 발송 자동화 — 메일 제공자 키 필요.

## 14. 알려진 이슈 / 주의
- **관리자 비번 설정 흐름**: 재설정/초대 메일 링크 클릭 → 대시보드의 "비밀번호 설정" 폼에서 본인이 입력. (이전엔 폼이 없어 로그인만 됐던 버그 → `4140d83`에서 수정.) 로그인 상태면 우상단 "비밀번호 변경"으로도 설정. **AI는 비밀번호를 설정하지 않음(정책).**
- **Supabase 무료 SMTP 발송 한도** — 초대/재설정 메일이 안 올 수 있음. 안 오면 잠시 후 재시도 또는 Auth→Emails에 SMTP 설정.
- **Cavalier 무료 티어**: 도메인 단위 집계 + URL 까지(개별 이메일은 search-by-email로 단건만, 전수 식별은 유료).
- **로컬 빌드 `--webpack` 필수**(9절).

## 15. 검증 명령
```bash
npm run typecheck                                   # 통과
NEXT_OUTPUT=export PAGES_BASE_PATH=/darkweb-monitor-dashboard npm run build -- --webpack  # 성공
curl -s "{URL}/rest/v1/breach_findings?select=finding_id" -H "apikey: {ANON}" -H "Authorization: Bearer {ANON}"  # → [] (RLS 잠금 확인)
# 라이브: https://duelspost-droid.github.io/darkweb-monitor-dashboard/ → 관리자 로그인 게이트
```
