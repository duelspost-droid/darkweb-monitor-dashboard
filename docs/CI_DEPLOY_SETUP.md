# #5 Edge 함수 CI 자동배포 설정

지금은 Edge 함수(`scan-breaches`)를 **Supabase 대시보드에서 수동 배포**합니다(대시보드가 느리면 막힘). 아래를 한 번 설정하면 `supabase/functions/**` 변경을 `main`에 푸시할 때 **GitHub Actions가 자동 배포**합니다.

> ⚠️ Claude가 쓰는 gh 토큰에는 `workflow` 스코프가 없어 **`.github/workflows/` 파일은 Claude가 푸시할 수 없습니다.** 그래서 이 파일(워크플로 YAML)은 **직접 추가**하셔야 합니다.

## 1) Supabase 액세스 토큰 발급
1. https://supabase.com/dashboard/account/tokens → **Generate new token** (이름 예: `gh-actions-deploy`)
2. 토큰 값 복사 (한 번만 표시됨)

## 2) 레포 시크릿 등록
GitHub 레포 → **Settings → Secrets and variables → Actions → New repository secret**
- Name: `SUPABASE_ACCESS_TOKEN`
- Value: 위 토큰

## 3) 워크플로 파일 추가
아래 내용을 **`.github/workflows/deploy-edge.yml`** 로 커밋(직접 추가):

```yaml
name: Deploy Edge Functions

on:
  push:
    branches: [main]
    paths:
      - 'supabase/functions/**'
  workflow_dispatch: {}

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: supabase/setup-cli@v1
        with:
          version: latest
      - name: Deploy scan-breaches
        env:
          SUPABASE_ACCESS_TOKEN: ${{ secrets.SUPABASE_ACCESS_TOKEN }}
        run: |
          supabase functions deploy scan-breaches \
            --project-ref elaoeffpzrswpdpfuoil \
            --no-verify-jwt
```

## 핵심 메모
- **`--no-verify-jwt` 필수**: 이 함수는 `verify_jwt=false` + `x-scan-secret` 공유시크릿으로 보호됩니다(대시보드 수동배포 때와 동일 동작 유지). 이게 빠지면 cron 호출이 401 날 수 있습니다.
- **시크릿은 건드리지 않음**: 함수의 환경변수(`SCAN_SECRET`·`MONITORED_*`·`GITHUB_TOKEN` 등)는 Supabase Secrets에 그대로 있으므로 배포가 덮어쓰지 않습니다.
- **수동 트리거**: Actions 탭 → Deploy Edge Functions → Run workflow (`workflow_dispatch`).
- 설정 후엔 `supabase/functions/scan-breaches/index.ts` 푸시 = 자동배포 → **대시보드 수동 monaco 주입 불필요**. (오늘 같은 대시보드 지연에도 안 막힘)

## 대안: 프런트와 동일 파이프라인
프런트 배포 워크플로(`deploy.yml`)는 이미 있습니다. 위 job을 거기에 한 step으로 합쳐도 됩니다(단, `SUPABASE_ACCESS_TOKEN` 시크릿 동일 필요).
