# 다크웹 유출 모니터링 대시보드 (Credential Leak Monitor)

회사 도메인 계정이 **다크웹·유출 데이터셋에 노출**됐는지 매일 자동으로 조회하고,
웹 대시보드에 **마스킹된 형태로 기록**하는 Next.js 앱입니다.

> 다크웹 마켓·포럼을 직접 크롤링하지 않습니다. 검증된 유출 인텔리전스 API
> (**Have I Been Pwned 도메인 검색**)로 *유출 사실만* 조회하며, 평문 비밀번호는 받지 않습니다.

## 주요 기능

- 🔍 **매일 자동 스캔** — 회사 도메인 계정의 유출 여부 조회 (GitHub Actions 스케줄)
- 🛡 **마스킹 기록** — 계정은 항상 `jo***@domain` 형태로만 저장/표시
- 📊 **대시보드** — KPI(노출 계정·신규·심각도), 심각도/도메인 분포, 상세표, 스캔 이력
- 🔔 **신규 탐지** — 직전 스캔 대비 새로 발견된 유출을 `NEW` 로 강조
- 🗄 **선택적 Supabase 적재** — `breach_findings` 테이블에 결과 저장

## 빠른 시작

```bash
npm install
npm run security:scan   # 스캔 실행 (HIBP_API_KEY 없으면 데모 데이터)
npm run dev             # http://localhost:3000
```

## 실데이터 전환

기본은 **데모 데이터**입니다. 실제 유출 데이터로 전환하려면:

1. https://haveibeenpwned.com/API/Key 에서 API 키 발급 (유료 구독)
2. HIBP 대시보드에서 모니터링할 **도메인 소유 검증**
3. `.env.local` 에 `HIBP_API_KEY=...` 등록 (CI 는 GitHub Secret)
4. `data/security/monitor_config.json` 의 `domains` 를 회사 도메인으로 설정

```json
{
  "domains": ["your-company.com"],
  "extraAccounts": [],
  "minSeverity": "low"
}
```

## 동작 구조

```
scripts/monitor_breaches.mjs        ← 수집기 (HIBP 조회 → 마스킹 → 생성)
  └─ data/security/monitor_config.json   대상 도메인 설정
  └─ data/security/latest_breach_scan.json   원본 기록 + 이력
  └─ data/security/history/*.json            스캔 스냅샷
  └─ lib/data/generated/breachMonitor.ts     정적 사이트가 임포트(자동 생성)

app/page.tsx                        ← 대시보드 (생성된 데이터 임포트)
lib/types/breachMonitor.ts          ← 도메인 타입
supabase/migrations/001_*.sql       ← breach_findings 테이블(선택)
```

매일 GitHub Actions 가 `security:scan` → 빌드 → 배포를 수행하고, 생성된 결과를 커밋합니다.

## 개인정보·보안 원칙

- 계정은 **마스킹**된 형태로만 저장. 평문 비밀번호·전체 이메일·기타 식별자 미저장.
- 유출 확인 계정은 즉시 **비밀번호 재설정 + MFA** 적용을 권고하고, 동일 비밀번호를
  재사용한 다른 서비스도 점검해야 합니다.
- 본 도구는 합법적 유출 인텔리전스 조회만 수행합니다.

## 스택

Next.js 16 (App Router) · TypeScript · Tailwind CSS · lucide-react
