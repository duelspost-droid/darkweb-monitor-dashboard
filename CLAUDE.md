# Claude Code — 프로젝트 지침

> **이어서 작업할 땐 `docs/HANDOFF.md` 를 먼저 보세요.** (작업 이력·결정·다음 TODO 전부 거기 있음)

## 프로젝트

- 이름: **다크웹 유출 모니터링 대시보드** (`darkweb-monitor-dashboard`)
- 목적: 회사 도메인 계정의 다크웹·유출 노출을 매일 자동 조회 → 웹 대시보드에 마스킹 기록
- 스택: Next.js 16 (App Router) · TypeScript · Tailwind CSS · lucide-react
- 데이터 방식: **합법 유출 인텔리전스 API(Have I Been Pwned 도메인 검색)**.
  다크웹 직접 크롤링 금지. 평문 비밀번호 미수신.

## 핵심 파일 (수정 위치)

| 목적 | 파일 |
|------|------|
| 수집 로직 | `scripts/monitor_breaches.mjs` |
| 모니터링 대상 도메인 | `data/security/monitor_config.json` |
| 대시보드 UI | `app/page.tsx` |
| 도메인 타입 | `lib/types/breachMonitor.ts` |
| 자동 생성(편집 금지) | `lib/data/generated/breachMonitor.ts` |

## 데이터 흐름

```
scripts/monitor_breaches.mjs
  ← data/security/monitor_config.json (대상 도메인)
  → data/security/latest_breach_scan.json (+ history/*.json)
  → lib/data/generated/breachMonitor.ts  (정적 사이트가 import)
app/page.tsx → breachScan 임포트해 렌더 (서버 컴포넌트)
```

## 중요한 제약 (보안·개인정보)

- 계정은 **항상 마스킹**(`jo***@domain`)으로만 저장·표시. 전체 이메일/로컬파트 저장 금지.
- 평문 비밀번호, 인증 토큰 값, 기타 개인식별자 저장 금지(노출 "항목 분류"만 보관).
- 다크웹 직접 크롤링·유출 덤프 직접 다운로드 금지. 인텔 API 조회만.

## 명령

```bash
npm run security:scan   # 스캔 (HIBP_API_KEY 없으면 데모 데이터)
npm run dev             # 개발 서버
npm run typecheck       # 타입 체크
npm run build           # 빌드 (정적 export: NEXT_OUTPUT=export)
```

## 실데이터 전환

`HIBP_API_KEY` 발급(유료) + HIBP 대시보드 도메인 소유 검증 → `.env.local`/GitHub Secret 등록 →
`monitor_config.json` 의 `domains` 설정 → `npm run security:scan`. 자세한 절차는 HANDOFF 5절.

## CI/CD

`.github/workflows/deploy.yml` — 매일 16:00 UTC(01:00 KST) 스캔 → 빌드 → GitHub Pages 배포 +
생성 결과 자동 커밋. Pages: Settings → Pages → Source = GitHub Actions. 프로젝트 사이트면
`PAGES_BASE_PATH=/darkweb-monitor-dashboard`(deploy.yml 에 이미 설정).
