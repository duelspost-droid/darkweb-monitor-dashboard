# 작업 핸드오프 — 다크웹 유출 모니터링 대시보드

> 다른 PC / 다음 세션에서 이어서 작업하기 위한 기록. 최신순.

## 1. 프로젝트 개요

- **이름**: `darkweb-monitor-dashboard` (Credential Leak Monitor)
- **목적**: 회사 도메인 계정이 다크웹·유출 데이터셋에 노출됐는지 **매일 자동 조회**하고,
  웹 대시보드에 **마스킹된 형태로 기록**.
- **스택**: Next.js 16 (App Router, Turbopack) · TypeScript · Tailwind CSS · lucide-react
- **출신**: 원래 `foreign-resident-finance-dashboard` 안의 `/security` 페이지로 구현했다가,
  성격이 다른 별도 제품이라 **독립 신규 프로젝트로 분리**(사용자 결정).
- **GitHub**: 아직 미생성. 사용자가 `duelspost-droid/darkweb-monitor-dashboard`(Public) 생성 예정.

## 2. 현재 상태 (✅ 완성·검증)

| 검증 | 결과 |
|------|------|
| `npm install` | ✅ 정상 |
| `npm run typecheck` | ✅ 통과 |
| `npm run build` (정적 export) | ✅ `/` 페이지 생성 성공 |
| `npm run security:scan` | ✅ 데모 스캔 9건 생성 |

- 기본은 **데모 데이터**(HIBP_API_KEY 미설정). `isDemo:true` 배너 표시.
- git: 단일 커밋 `feat: 다크웹 유출 계정 모니터링 대시보드 (신규 독립 프로젝트)` 존재.
  (원격(origin)은 제거된 상태 — 새 repo 만들고 직접 add.)

## 3. 작업 이력 (세션별)

### 2026-06-21 세션 (opus, 리모트 환경)
사용자 지시 흐름:
1. "다크웹을 매일 검색해서 회사 계정 유출된 거 찾아 웹에 기록" → 기능 설계.
2. "로컬에서 작업하자" → 합법 유출 인텔 API(HIBP) 방식으로 구현(다크웹 직접 크롤링 X).
3. "신규 프로젝트니깐 git 저장소를 신규 프로젝트로 이전" → 깨끗한 독립 앱으로 분리.
   - 결정: **깨끗한 독립 앱** / 이름 **darkweb-monitor-dashboard** / **Public**.

구현한 것:
- `scripts/monitor_breaches.mjs`: HIBP 도메인 검색 API 수집기.
  - 키 있으면 `GET /api/v3/breacheddomain/{domain}` 으로 실조회, 공개 `/breaches` 메타로 보강.
  - 키 없으면 **데모 데이터** 생성(잘 알려진 유출 사건 메타 기반, `isDemo:true`).
  - 직전 스캔과 비교해 **신규(isNew)** 표시, 이력 타임라인 누적.
  - 계정은 항상 **마스킹**(`jo***@domain`)으로만 저장. 평문 비밀번호·전체 이메일 미저장.
  - 출력: `data/security/latest_breach_scan.json`, `history/breach_scan_*.json`,
    `lib/data/generated/breachMonitor.ts`(정적 사이트 임포트용).
  - Supabase env 있으면 `breach_findings` 테이블에 최선노력 upsert.
- `app/page.tsx`: 대시보드(KPI 4종·심각도 분포·도메인별 분포·유출 상세표·스캔 이력·운영 안내).
- `lib/types/breachMonitor.ts`: 도메인 타입.
- `components/ui/`: PageHero·Panel·StatTile·BarList (원본 대시보드에서 가져와 독립화).
- `app/layout.tsx` + `app/globals.css`: 사이드바 없는 단일 페이지용 상단바 + 프리미엄 스타일.
- `supabase/migrations/001_breach_monitoring.sql`: `breach_findings` 테이블(RLS 포함, 선택).
- `.github/workflows/deploy.yml`: 매일 16:00 UTC 스캔 → 빌드 → GitHub Pages 배포 + 결과 커밋.

**블로커(리모트 환경 한계)**:
- 리모트 클라우드 환경에서 **새 GitHub repo 생성 불가**(`create_repository` 403),
  다른 repo로 git push 불가(프록시가 현재 repo만 인가). → 사용자가 직접 repo 생성/푸시 필요.
- 그래서 프로젝트를 **tar.gz 로 사용자에게 직접 전달**.

## 4. 로컬에서 이어서 작업하기

```bash
# 1) 압축 해제 (전달받은 tar.gz)
tar xzf darkweb-monitor-dashboard.tar.gz
cd darkweb-monitor-dashboard

# 2) GitHub에 빈 repo 'darkweb-monitor-dashboard'(Public) 생성 후 연결·푸시
git remote add origin https://github.com/duelspost-droid/darkweb-monitor-dashboard.git
git push -u origin main

# 3) 개발
npm install
npm run security:scan        # 스캔 (HIBP_API_KEY 없으면 데모)
npm run dev                  # http://localhost:3000
npm run typecheck && npm run build
```

## 5. 실데이터 전환 (현재 데모 → 실제 유출 조회)

1. https://haveibeenpwned.com/API/Key 에서 API 키 발급(유료 구독).
2. HIBP 대시보드에서 모니터링할 **도메인 소유 검증**(도메인 검색의 전제조건).
3. `.env.local` 에 `HIBP_API_KEY=...` (CI 는 GitHub Secret `HIBP_API_KEY`).
4. `data/security/monitor_config.json` 의 `domains` 를 회사 도메인으로 설정.
   ```json
   { "domains": ["jbfg.com"], "extraAccounts": [], "minSeverity": "low" }
   ```
5. `npm run security:scan` 재실행 → `isDemo:false` 실데이터로 전환.

## 6. 다음 작업 TODO (우선순위)

### 단기
- [ ] GitHub repo 생성 + 첫 푸시(위 4번).
- [ ] GitHub Pages 활성화(Settings → Pages → Source: GitHub Actions). 워크플로는 이미 있음.
      프로젝트 사이트면 basePath `/darkweb-monitor-dashboard` 가 deploy.yml 에 설정됨.
- [ ] `HIBP_API_KEY` 발급·도메인 검증 후 실데이터 전환(5번).

### 중기 (기능 확장)
- [ ] **알림**: 신규(isNew) 유출 발견 시 Slack/이메일 웹훅 전송(scripts 에 notify 단계 추가).
- [ ] **대상 다건**: monitor_config 에 여러 도메인/개별 계정(extraAccounts) 운영.
- [ ] **조치 추적**: 발견 항목별 "처리 상태"(비밀번호 재설정 완료 등) 토글 — Supabase 컬럼 추가.
- [ ] **이력 차트**: 스캔 이력(history)을 Recharts 라인차트로(현재는 리스트). recharts 의존성 추가 필요.
- [ ] **HIBP 페이지네이션/레이트리밋**: 대형 도메인 대비 429 백오프, `Retry-After` 처리.
- [ ] **추가 소스(선택)**: DeHashed/IntelX/LeakCheck 등 — 각 API 키·약관 검토 후 콜렉터 추가.

### 운영/품질
- [ ] 스캔 이력 스냅샷(`data/security/history/*.json`)이 누적되므로 보존 기간 정책(예: 90일) 정리.
- [ ] Supabase 연동 시 `001_breach_monitoring.sql` 적용 + `SUPABASE_URL`/`SERVICE_ROLE_KEY` 설정.

## 7. 파일 구조

```
darkweb-monitor-dashboard/
├─ app/
│  ├─ page.tsx              대시보드(서버 컴포넌트, breachScan 임포트)
│  ├─ layout.tsx            상단바 + 컨테이너
│  └─ globals.css           프리미엄 스타일(hero/surface/stat-tile/chip/barlist)
├─ components/ui/           PageHero·Panel·StatTile·BarList
├─ lib/
│  ├─ types/breachMonitor.ts            도메인 타입
│  └─ data/generated/breachMonitor.ts   ★자동 생성(편집 금지) — 페이지가 임포트
├─ scripts/monitor_breaches.mjs         수집기(이 파일을 수정)
├─ data/security/
│  ├─ monitor_config.json   ★대상 도메인 설정(여기 수정)
│  ├─ latest_breach_scan.json   원본 기록
│  └─ history/*.json            스캔 스냅샷
├─ supabase/migrations/001_breach_monitoring.sql
├─ .github/workflows/deploy.yml
└─ README.md · package.json · tsconfig.json · tailwind.config.ts · next.config.mjs
```

## 8. 개인정보·보안 원칙

- 계정은 **마스킹**된 형태로만 저장. 평문 비밀번호·전체 이메일·기타 식별자 미저장.
- 다크웹 직접 크롤링 금지 — 합법 유출 인텔리전스 API 조회만 수행.
- 유출 확인 계정은 즉시 **비밀번호 재설정 + MFA** 권고, 동일 비밀번호 재사용 서비스 점검.

## 9. 검증 명령

```bash
npm install
npm run typecheck                                   # 성공
NEXT_OUTPUT=export PAGES_BASE_PATH=/darkweb-monitor-dashboard npm run build  # 성공
npm run security:scan                               # 스캔(데모/실데이터)
npm run dev                                          # http://localhost:3000
```
