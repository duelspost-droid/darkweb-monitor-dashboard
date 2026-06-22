# Claude Code — 프로젝트 지침

> **이어서 작업할 땐 `docs/HANDOFF.md` 를 먼저 보세요.** (작업 이력·결정·다음 TODO 전부 거기 있음)

## 프로젝트

- 이름: **다크웹 유출 모니터링 대시보드** (`darkweb-monitor-dashboard`)
- 목적: 회사 도메인 계정의 다크웹·유출 노출을 매일 자동 조회 → 웹 대시보드에 마스킹 기록
- 스택: Next.js 16 (App Router) · TypeScript · Tailwind CSS · lucide-react
- 데이터 방식: **합법 유출 인텔리전스 API** (다크웹 직접 크롤링 금지, 평문 비밀번호 미수신).
  - breach(계정 유출): **XposedOrNot**(무료, 계정별) · **HIBP**(유료키, 도메인 전수 — 임직원 "전수"는 이 경로) · **IntelX**(키-게이트, 도메인) · **LeakCheck**(키=v2 도메인/무키=public 계정별).
  - infostealer: **Hudson Rock Cavalier** — `search-by-domain`(무료, 도메인 집계) + `search-by-email`(무료, 계정별 → breach_findings, 민감값 미저장·분류만).
  - 보조 소스는 키 있으면 사용/없으면 skip, 결과는 finding 별 `source` 라벨 + `sources[]` provenance 기록. 환경변수는 `.env.example` (C)/(D) 참고.
- 백엔드: **Supabase** (breach_findings·scan_runs). 매일 자정(KST) Edge Function+pg_cron 으로 수집.

## 핵심 파일 (수정 위치)

| 목적 | 파일 |
|------|------|
| 로컬/CI 수집 로직 | `scripts/monitor_breaches.mjs` |
| 자정 배치(서버) | `supabase/functions/scan-breaches/index.ts` (Deno) |
| Supabase→정적사이트 동기화 | `scripts/pull_from_supabase.mjs` |
| DB 스키마 | `supabase/migrations/00*.sql` |
| 모니터링 도메인(공개) | `data/security/monitor_config.json` |
| 모니터링 이메일(비공개·gitignore) | `data/security/monitor_config.local.json` |
| 대시보드 UI | `app/page.tsx` |
| 도메인 타입 | `lib/types/breachMonitor.ts` |
| 자동 생성(편집 금지) | `lib/data/generated/breachMonitor.ts` |

## 데이터 흐름

```
[서버·매일 자정] pg_cron(15:00 UTC) → Edge Function scan-breaches
   → XposedOrNot/HIBP 조회 → Supabase breach_findings + scan_runs (마스킹)
[빌드] GitHub Actions(15:30 UTC) → npm run supabase:pull
   → Supabase REST 읽기 → lib/data/generated/breachMonitor.ts → 정적 빌드 → Pages
[로컬] npm run security:scan (monitor_config.local.json accounts → XposedOrNot)
   → latest_breach_scan.json + generated/breachMonitor.ts
app/page.tsx → breachScan 임포트해 렌더 (서버 컴포넌트)
```

## 중요한 제약 (보안·개인정보)

- 계정은 **항상 마스킹**(`jo***@domain`)으로만 저장·표시. 전체 이메일/로컬파트 저장 금지.
- 평문 비밀번호, 인증 토큰 값, 기타 개인식별자 저장 금지(노출 "항목 분류"만 보관).
- 다크웹 직접 크롤링·유출 덤프 직접 다운로드 금지. 인텔 API 조회만.

## 명령

```bash
npm run security:scan        # 로컬 스캔 (accounts 있으면 실데이터, 없으면 데모)
npm run supabase:pull        # Supabase → 생성 파일 동기화 (SUPABASE_* 필요)
npm run dev -- --webpack     # 개발 서버 (★로컬은 --webpack 필수, 아래 참고)
npm run typecheck            # 타입 체크
npm run build -- --webpack   # 정적 export 빌드 (NEXT_OUTPUT=export PAGES_BASE_PATH=/darkweb-monitor-dashboard)
```

> ⚠️ **로컬은 `--webpack` 필수**: Codex.app 번들 node 로 설치한 `@next/swc-darwin-arm64` 네이티브
> 바인딩이 코드서명 Team ID 불일치로 로드 거부 → Turbopack(기본) 실패, WASM 폴백만 됨.
> dev/build 모두 `-- --webpack` 붙일 것. CI(정식 node)에선 불필요.

## 실데이터 / Supabase 배포

무료(권장): `monitor_config.local.json` 의 `accounts` 에 실계정 → `npm run security:scan`.
Supabase 백엔드 배포(자격증명 필요)와 cron·Edge Function·Vault 절차는 **HANDOFF 5-B절** 참고.

## CI/CD

`.github/workflows/deploy.yml` — 매일 **15:30 UTC(00:30 KST)** Supabase pull → 빌드 → Pages 배포.
(스캔 자체는 Supabase pg_cron 이 15:00 UTC 수행.) Pages: Settings → Pages → Source = GitHub Actions.
`PAGES_BASE_PATH=/darkweb-monitor-dashboard`(deploy.yml 에 설정). GitHub Secrets: `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`.
